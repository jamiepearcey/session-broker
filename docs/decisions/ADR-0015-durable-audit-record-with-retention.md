# ADR-0015: The audit record is a table in the broker's own store, kept for a bounded window and surfaced in the console

## Status

Accepted (2026-07-27). Implements plane 2 of
[ADR-0014](ADR-0014-observability-two-planes.md).

## Context

ADR-0014 rules that the audit record must not be a log stream. This ADR decides
where it lives, what it costs on the request path, how long it is kept, and who
can read it.

The constraints are specific to this service:

- The store is embedded SQLite with **one writer thread** that already batches
  every queued mutation into a single transaction every ≤50 ms
  (`store::writer`). An audit row is therefore nearly free *if it rides an
  existing batch*, and it is the only place in the system where an audit row and
  the state change it records can be made atomic without inventing anything.
- Sessions are **memory-primary with write-behind** and rotation is
  non-invalidating, so losing the last few milliseconds of session writes in a
  crash is already accepted (§5). The audit record must not silently inherit
  that tolerance for the events where it matters.
- `security/iam` ADR-0011/0024 set the house shape: fail-closed durable sink,
  fail-open log sink, no secret material, append-only, and a query API. This is
  the same model expressed for a single-writer embedded store instead of
  Postgres.

## Decision

### One table, schema v3, append-only

```sql
CREATE TABLE audit (
  seq              INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic; gaps are visible
  at               INTEGER NOT NULL,                   -- epoch secs
  action           TEXT    NOT NULL,                   -- stable dotted name
  outcome          TEXT    NOT NULL,                   -- success | failure
  actor_kind       TEXT    NOT NULL,                   -- admin | backend | user | system | anonymous
  actor_id         TEXT,                               -- key_id, sub, or NULL
  subject          TEXT,                               -- whose data was acted on
  sid              TEXT,
  custody_id       TEXT,
  key_id           TEXT,
  reason           TEXT,                               -- the refusal code, on failure
  client_ip_prefix TEXT,                               -- /24 or /48, never a full address
  detail           TEXT                                -- non-secret JSON
);
```

`AUTOINCREMENT` is deliberate: `seq` never reuses a value even after a prune, so
it is a stable pagination cursor *and* a gap in it is evidence rather than
ambiguity.

Append-only by policy and by test: nothing in `repo` issues `UPDATE audit` or a
`DELETE` other than the retention prune, and a test asserts it.

### Two tiers, decided by whether the event grants or removes power

**Tier A — transactional (fail-closed).** The audit row is carried *inside the
same writer command* as the state change and applied in the same transaction. It
is impossible to have the change without the row, or the row without the change.
If the transaction fails, the handler returns 500 and nothing happened.

Tier A covers exactly the events that change who can do what:

- `key.issued`, `key.revoked` — the credential that can act as any user
- `session.revoked` — an operator forcing a user out
- `logging.level_changed` — turning the diagnostic plane up or down

**Tier B — best-effort, counted (fail-open).** Everything else with audit value
but no power transfer. Enqueued on the writer's channel and forgotten by the
caller; batched like any other write-behind mutation.

- `session.created`, `session.logged_out`
- `login.failed` (with the refusal reason; failures are audited even for unknown
  subjects, per the house threat model)
- `token.exchanged`, `token.refused` — a backend acting for a user
- `custody.degraded`, `custody.dead`, `custody.revoked_upstream`
- `session.anomaly` — INV-6a's signals, which had no home before this
- `audit.gap` — see below

Tier B has a **depth bound** (`audit_queue_capacity`, default 8192 in flight). At
the bound, events are dropped, `broker_audit_dropped_total` increments, and the
first event accepted after the queue drains is a synthetic `audit.gap` row
carrying the number dropped. **A record that is incomplete says so.** A silent
short record is the failure mode this exists to prevent.

Tier A is not subject to the bound. It cannot be, and it does not need to be:
those events arrive at operator speed, not request speed.

### Nothing on the hot path writes a row

`/session/refresh` (INV-8) and `/authz` produce **metrics only**, on success and
on refusal alike. An authz denial is a counter by reason plus one log line; it
changed nothing, so it is not history. This is the whole latency answer, and it
is a consequence of what the record is for, not a shortcut taken for speed.

Generation rotation is likewise not recorded by default
(`audit_record_rotations=false`): rotation happens per session per few minutes
across the whole fleet, and the interesting rotations — use of a superseded or
reaped generation, two generations from different IP prefixes — are already
`session.anomaly` events, which are always recorded.

`token.exchanged` is **coalesced per `(key_id, sid)` per `audit_coalesce_secs`**
(default 300). The audit fact is "backend `envoy-edge` acted for `user-1` this
afternoon", not the ten thousand times it did so. `token.refused` is never
coalesced — a refusal is always interesting. This mirrors the throttle already
applied to `api_key.last_used_at`, for the same reason.

### Retention: a bounded hot window, not an archive

`audit_retention_days`, default **90**, pruned hourly by a task that sends one
`PruneAudit` command to the writer. `0` disables pruning (keep forever — an
explicit choice, not the default, because an unbounded table in an embedded
SQLite file eventually becomes an incident).

The broker keeps a **queryable window**; the log stream is the archive. Every
audit row is also emitted to `broker::audit` at `info` (fail-open, ADR-0014), so
a deployment that needs seven-year retention gets it from the collector it
already runs, and the broker's own file stays a working set. Deployments with no
collector should raise `audit_retention_days` and know they have chosen the
broker's disk as their system of record.

### Reading it

`GET /admin/audit` on the internal listener behind the admin key, filterable by
time range, action prefix, subject, outcome and actor, paginated with a
`before_seq` cursor, and exportable as NDJSON. Surfaced in the console as an
**Audit trail** view, alongside an **Observability** view showing what the
diagnostic plane is currently doing.

### Subjects are pseudonymisable

`audit_subject_mode = plain | hashed` (default `plain`). Under `hashed`, `sub`
and `actor_id` are stored as a truncated SHA-256 keyed by the custody keyfile —
stable, so correlation across rows still works, but the record no longer names
people. Deployments that must retain audit under a data-minimisation regime turn
this on; most will not.

## Alternatives considered

- **A second SQLite file for audit.** Rejected: it forfeits the single
  transaction with the state change, which is the entire Tier A guarantee, and
  doubles the fsync surface.
- **Postgres for audit only.** Rejected for v1 — it would make the broker's
  first hard external dependency an *observability* one, which inverts the
  priority. The schema is plain relational and ports with the rest under ADR-0005
  when the HA path is taken.
- **Fail-closed for everything.** Rejected: making `login`, `logout` and
  `token.exchanged` fail-closed means a full disk logs the whole platform out.
  Tier A is drawn exactly at the events where refusing to act is better than
  acting unrecorded.
- **Fail-open for everything.** Rejected: it permits silently issuing a
  credential with no record, which is the repudiation risk the record exists for.
- **Unbounded Tier B queue.** Rejected: it converts a stuck writer thread into
  unbounded memory growth in the credential custodian. A bounded queue with an
  honest gap marker is the better failure.
- **Hash-chained / tamper-evident rows.** Deferred, as `security/iam` ADR-0011
  also deferred it. The rows are immutable and the columns leave room for a
  `prev_hash`; v1 relies on append-only behaviour plus the fact that the file is
  reachable only from the internal listener.

## Consequences

- Schema v3. Migrations are forward-only and already idempotent; no backfill —
  history starts when this ships, and the first row says so.
- An audit-write failure can fail an admin mutation. That is the accepted
  availability/repudiation trade-off, identical to `security/iam` ADR-0024's.
- Operators must treat `broker_audit_dropped_total > 0` as production-critical:
  it means the record has a hole.
- Adding a new security-sensitive operation now requires an `action` name, a tier,
  and a test proving the row is emitted without secret material.
- The console gains two views and the admin lane gains four endpoints; the browser
  path and the `/authz` path gain nothing at all, which is the point.
