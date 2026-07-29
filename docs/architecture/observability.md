# Observability & the audit record

The operator-facing plan behind
[ADR-0014](../decisions/ADR-0014-observability-two-planes.md) (two planes) and
[ADR-0015](../decisions/ADR-0015-durable-audit-record-with-retention.md) (the
durable record). Read those for *why*; this is *what*, *where*, and *how to wire
it up*.

---

## 1. The shape in one picture

```
                    ┌──────────────────────────────────────────┐
   /authz  ────────▶│  metrics only  (atomics, no I/O)         │──▶ GET /metrics
   /session/refresh │                                          │    (internal listener,
                    └──────────────────────────────────────────┘     Prometheus pull)

                    ┌──────────────────────────────────────────┐
   everything ─────▶│  tracing  ──▶ bounded queue ──▶ writer    │──▶ stdout (JSON|text)
                    │              thread (non-blocking)       │──▶ optional file
                    └──────────────────────────────────────────┘        │
                                                                        ▼
                                                              sidecar / node agent
                                                              (Vector, Fluent Bit,
                                                               Promtail, journald)
                                                                        │
                    ┌──────────────────────────────────────────┐        ▼
   power-granting ─▶│  audit row IN THE SAME TRANSACTION       │      SIEM / archive
   state changes    │  as the change it records  (Tier A)      │      (forever)
                    ├──────────────────────────────────────────┤
   other security ─▶│  audit row, batched, depth-bounded,      │
   events           │  drops counted + gap-marked  (Tier B)    │
                    └──────────────────┬───────────────────────┘
                                       ▼
                            SQLite `audit` table
                       bounded window (default 90 days)
                                       │
                                       ▼
                    GET /admin/audit → console "Audit trail"
```

The one rule that makes this fast: **a request that changes nothing produces no
row.** Everything on the per-request path — every Envoy `ext_authz` call, every
session refresh — costs one atomic add and (at `info`) one non-blocking log
line. Neither touches the store.

---

## 2. Answering the questions this design was asked

**"Is this one for a log sidecar and to filesystem, or something more advanced?"**

Both, and neither is the whole answer, because the two things being asked about
are different planes.

- For **diagnostics**: yes, a sidecar. The broker writes structured JSON to
  stdout and nothing else. The deployment's collector — a Vector/Fluent Bit
  sidecar, a DaemonSet node agent, or `journald` on a box — owns transport,
  buffering, retry and retention. The broker owning any of that would mean an
  outbound, blockable network path inside the process that holds every user's
  refresh token, which is a worse trade than losing a debug line. The filesystem
  sink exists for deployments with no collector and is explicitly the fallback.
- For **audit**: no. A sidecar is exactly what an audit record must not depend
  on. A record whose completeness is a function of a collector's configuration
  cannot answer "prove nobody issued a key that week". That is why plane 2 is a
  transactional table in the broker's own store, queryable by the console
  without any external system being present or healthy.

**"Latency is a concern but so is auditing."**

They stop competing once you notice they want different events. The
high-frequency events (authz allow, refresh success) have no audit value —
recording them ten thousand times adds nothing an investigator would read. The
audit-valuable events (a key issued, a session force-revoked, a grant going
dead, a backend acting for a user) arrive at human or background-worker speed.
So the hot path pays atomics, and the audit path pays a batched SQLite write it
was going to make anyway.

**"Perhaps we need to maintain audit history for some time and surface it?"**

Yes — 90 days by default, in the store, with a console view over it. The
"for some time" is the important part: the broker keeps a *working set*, the log
archive keeps the long tail. An unbounded audit table inside an embedded SQLite
file is a future incident, so retention is on by default and switching it off is
a deliberate act.

---

## 3. Configuration

Every key is `BROKER_<KEY>` in the environment or a bare key in
`session-broker.toml`; environment wins.

### Diagnostics

| Key | Default | Meaning |
|---|---|---|
| `log_format` | `text` | `text` for humans, `json` for a collector. Set `json` anywhere with a shipper. |
| `log_level` | `session_broker=info,broker=info,tower_http=warn` | The default `EnvFilter` directive. `RUST_LOG`, if set, still wins over this. **Keep a `broker` directive.** This service's events carry explicit targets (`broker::audit`, `broker::http`, …) and `EnvFilter` matches the TARGET, not the crate — a filter naming only `session_broker` silently drops every one of them, audit stream included. |
| `log_file` | *(unset)* | Optional second sink. Unset means stdout only, which is the recommended deployment. |
| `log_file_rotation` | `daily` | `daily`, `hourly` or `never`. Rotation only; **pruning old files is the deployment's job** (logrotate, a retention policy on the volume) — the broker does not delete files it has closed. |
| `log_queue_capacity` | `16384` | Lines buffered before the writer thread drops. Drops are reported on stderr by the appender and counted. |
| `log_level_override_max_secs` | `3600` | Ceiling on a console-requested temporary verbosity change. |
| `metrics_enabled` | `true` | Serves `GET /metrics` on the internal listener. |

### Audit

| Key | Default | Meaning |
|---|---|---|
| `audit_retention_days` | `90` | Rows older than this are pruned hourly. `0` = keep forever (see ADR-0015 before choosing it). |
| `audit_queue_capacity` | `8192` | Tier-B in-flight bound. At the bound, events drop and a gap is recorded. |
| `audit_coalesce_secs` | `300` | Window in which repeated `token.exchanged` for the same `(key_id, sid)` collapse to one row. Refusals never coalesce. |
| `audit_record_rotations` | `false` | Record every generation rotation. High volume, low value — anomalous rotations are recorded regardless. |
| `reap_after_secs` | `86400` | How long a provably-dead session row is kept before the reaper removes it. `0` disables reaping, and the store then grows without bound. The audit record outlives these rows by design, so history is not what this prunes. |
| `audit_subject_mode` | `plain` | `hashed` stores `sub`/`actor_id` as a keyed truncated SHA-256: still correlatable, no longer naming people. |

---

## 4. Event catalogue

Stable dotted `action` names. Adding one is an additive change; renaming one is
a breaking change to whatever is alerting on it.

### Tier A — transactional, fail-closed

| Action | Actor | Recorded when |
|---|---|---|
| `key.issued` | `admin` | A backend API key is minted. `detail` carries the name; never the secret. |
| `key.revoked` | `admin` | A key is revoked. Effective immediately — the `revoked_at IS NULL` predicate *is* the revocation. |
| `session.revoked` | `admin` | An operator force-logs-out a session. |
| `logging.level_changed` | `admin` | Diagnostic verbosity raised or restored, with the deadline in `detail`. Turning the lights down is itself an audited act. |

### Tier B — batched, fail-open, depth-bounded

| Action | Actor | Recorded when |
|---|---|---|
| `session.created` | `user` | A login completes and a session is minted. |
| `session.logged_out` | `user` | The user logs out (tombstone, INV-7). |
| `login.failed` | `anonymous` | Callback validation fails — bad `state`, bad `nonce`, expired txn, IdP error. `reason` carries which. Audited even for unknown subjects. |
| `token.exchanged` | `backend` | `/internal/token` hands a backend the upstream token. Coalesced per `(key_id, sid)`. |
| `token.refused` | `backend` | `/internal/token` refuses. Never coalesced. |
| `custody.degraded` | `system` | Keepalive failed and the grant moved off `ok`. |
| `custody.dead` | `system` | The refresh token will never work again. |
| `custody.revoked_upstream` | `system` | The IdP revoked the grant; `detail` carries the `on_upstream_revoked` policy applied. |
| `session.anomaly` | `user` | INV-6a: a superseded or reaped generation was used, or two generations were used concurrently from different IP prefixes. `detail` carries which. **Signal, not revocation** — the row is the point. |
| `audit.gap` | `system` | Tier B dropped events. `detail.dropped` is how many. |

### Deliberately not audit events

`/authz` allow **or** deny, `/session/refresh` success, `/session` reads,
`/session/events` subscriptions, `/healthz`, `/metrics`. All are visible as
metrics; denials additionally get a log line each. None change state.

---

## 5. Field dictionary and redaction (INV-12)

**Permitted** in any log line, audit row or metric label:

`sid`, `sub` (or its pseudonym), `key_id`, `custody_id`, `gen_no`, `action`,
`outcome`, `reason`, `route` (the *matched pattern*, never the raw path),
`status`, `lane`, `client_ip_prefix` (/24 for IPv4, /48 for IPv6), `ua_hash`,
elapsed time.

**Forbidden**, without exception:

session cookie values, `broker_meta` contents, upstream access tokens, upstream
refresh tokens, PKCE verifiers, OAuth `state`, OIDC `nonce`, ID tokens, API key
secrets, `admin_api_key`, token hashes (they are a credential-equivalent
lookup key), full client IP addresses, raw `User-Agent` strings, raw request
paths (they carry `return_to` and `code`).

Enforced by `telemetry::tests::no_secret_material_reaches_any_sink`, which drives
the flows with known fixture secrets and greps the captured output — the same
technique that proved INV-5 by grepping the database file.

---

## 6. Metric catalogue

Prometheus text 0.0.4 at `GET /metrics` on the internal listener. Prefix
`broker_`. Histogram buckets start at **50 µs** because the refresh path's
headline claim is microseconds and a histogram that starts at 1 ms cannot show
it.

**Traffic and latency**
- `broker_http_requests_total{lane,route,status}` — `lane` ∈ `public|internal|admin`
- `broker_http_request_duration_seconds{lane,route}`

**Session state (gauges, sampled at scrape)**
- `broker_sessions_live`, `broker_generations_live`
- `broker_session_events_subscribers`
- `broker_custody{status}` — `ok|degraded|dead`

**Decisions**
- `broker_authz_decisions_total{decision,reason}` — the platform's per-request lane
- `broker_session_refresh_total{outcome}` — `rotated|coalesced|reused|refused`
- `broker_token_exchanges_total{outcome}`
- `broker_session_anomalies_total{kind}`

**Background work**
- `broker_keepalive_refresh_total{outcome}`
- `broker_keepalive_upstream_duration_seconds` — the only histogram measuring the IdP

**The observability plane's own health**
- `broker_audit_recorded_total{tier}`
- `broker_audit_dropped_total` — **alert on any increase**; the record has a hole
- `broker_audit_failed_total` — a Tier A transaction failed, so an operation was refused
- `broker_audit_queue_depth`, `broker_audit_rows`, `broker_audit_oldest_seconds`
- `broker_log_level_override_active` — 1 while someone has the lights turned up
- `broker_build_info{version}`

### Alerts worth having on day one

| Alert | Expression | Why |
|---|---|---|
| Audit gap | `increase(broker_audit_dropped_total[5m]) > 0` | The security record is incomplete. |
| Audit fail-closed firing | `increase(broker_audit_failed_total[5m]) > 0` | Admin mutations are being refused. |
| Grants dying | `broker_custody{status="dead"} > 0` | Users' backend calls will fail while their sessions look fine. |
| Authz latency | `histogram_quantile(0.99, broker_http_request_duration_seconds{route="/authz"}) > 0.005` | This is on every platform request. |
| Verbosity left on | `broker_log_level_override_active == 1` for > 1h | Someone raised it during an incident and forgot. |

---

## 7. Wiring up the log pipeline

### Kubernetes — sidecar

```yaml
# The broker writes JSON to stdout; the sidecar reads the container log file.
env:
  - name: BROKER_LOG_FORMAT
    value: json
# No BROKER_LOG_FILE: stdout is the interface.
```

```toml
# vector.toml — sidecar or node agent
[sources.broker]
type = "kubernetes_logs"
extra_label_selector = "app=session-broker"

# Split the two planes apart on the way out: audit goes to the archive that
# has to survive, diagnostics go wherever is cheap.
[transforms.split]
type = "route"
inputs = ["broker"]
route.audit = '.target == "broker::audit"'

[sinks.audit_archive]
type = "aws_s3"          # or splunk_hec, elasticsearch, loki…
inputs = ["split.audit"]
# Long retention lives HERE. The broker keeps 90 days for querying.

[sinks.diagnostics]
type = "loki"
inputs = ["split._unmatched"]
```

### systemd — no collector

```ini
[Service]
Environment=BROKER_LOG_FORMAT=json
ExecStart=/usr/local/bin/session-broker
StandardOutput=journal
```

`journalctl -u session-broker -o cat | jq 'select(.target=="broker::audit")'`
gets the audit stream out. If this box *is* the system of record, raise
`audit_retention_days` and back up `session-broker.db` — say so in the runbook
rather than discovering it.

### Filesystem sink

```
BROKER_LOG_FILE=/var/log/session-broker/broker.log
BROKER_LOG_FILE_ROTATION=daily
```

Rotation is by the broker; **deletion is not**. Point logrotate or a volume
retention policy at the directory, or it fills.

### Prometheus

```yaml
- job_name: session-broker
  static_configs:
    - targets: ["127.0.0.1:8090"]   # the INTERNAL listener
  metrics_path: /metrics
```

`/metrics` is unauthenticated, exactly like `/admin/*` is not: the listener's
network position is the control. If the internal listener is reachable from
somewhere it should not be, the token-exchange lane is a much larger problem than
the metrics.

---

## 8. Runtime controls, and where the line is

The console can change **how loud the diagnostics are**. It cannot change
**where the record goes**.

- `PUT /admin/observability/log-level` raises verbosity for a bounded duration
  and then restores itself. It is audited (Tier A), it is visible in
  `broker_log_level_override_active`, and it expires — nobody leaves the broker
  at `trace` for a month because they were debugging on a Friday.
- Sinks, retention, redaction and the audit tiers are **deployment config**,
  changed in the config file or environment and applied at restart.

The reason for the line is direct: a browser tool holding the admin key must not
be able to redirect or silence the audit stream. Blinding the record is precisely
what an attacker who reaches that console would want to do first, and "it needs a
config change and a restart" is a meaningfully higher bar than "it needs the
credential they already have".

---

## 9. Reading the record

`GET /admin/audit` (internal listener, admin key):

```
?since=<epoch>&until=<epoch>&action=key.        # prefix match
&subject=user-1&outcome=failure&actor_kind=admin
&limit=200&before_seq=<cursor>                  # descending, seq cursor
&format=ndjson                                  # export
```

In the console: **Audit trail** for the record itself, **Observability** for
what the diagnostic plane is currently doing, what it would need to be wired to
a collector, and the temporary-verbosity control.

---

## 10. Operational notes

- **History starts at deploy.** There is no backfill; the first row after
  migration to schema v3 is the beginning of the record. Say so in the change
  record rather than letting someone conclude a quiet week was a quiet week.
- **`audit.gap` rows are load-bearing.** If one appears, the window it covers is
  not evidence of absence. Alert on the counter, not on the row.
- **The store file grows with the window.** At 90 days and a busy deployment,
  budget on the order of a few hundred bytes per row. `broker_audit_rows` is
  exposed so this is a graph, not a surprise.
- **Backups.** `session-broker.db` now carries the audit record as well as
  custody. Whatever backup policy covers the custody keyfile should cover it,
  and the two must be backed up together — the file is useless without the key.
