# ADR-0014: Observability is two planes — lossy diagnostics and a durable audit record

## Status

Accepted (2026-07-27).

## Context

The broker had `tracing` wired to stdout with a default filter and nothing else:
no metrics, no request-level instrumentation, and no record of who did what. For
a service that holds every user's upstream refresh token, mints backend
credentials, and now answers Envoy's `ext_authz` on **every request in the
platform** (ADR-0015 in `finance/quant/pricing`), that is below the floor.

Two requirements pull in opposite directions and had been treated as one thing:

- **Latency.** `/authz` is on the per-request path of the whole platform and
  `/session/refresh` is the product's headline claim ("answers in microseconds",
  INV-8). Neither may acquire a syscall, a lock hold, or a disk write per call.
- **Accountability.** "Which backend obtained a token for this user", "who
  revoked that key", "when did this grant go dead" must be answerable *after the
  fact*, and answerable even if the log pipeline was misconfigured for a week.

A single log stream cannot serve both. Logs are allowed to be lossy — that is
what makes them cheap — and an audit trail that is allowed to be lossy is not an
audit trail. The house has already ruled on this twice: `security/iam` ADR-0011
rejected log-only audit as the system of record, and ADR-0024 made at least one
sink fail-closed.

## Decision

Split observability into **two planes with different guarantees**, and never let
the requirements of one degrade the other.

### Plane 1 — Diagnostics: lossy, cheap, shipped by the deployment

Logs, metrics and (optionally) traces. Loss is acceptable; blocking is not.

- **Logs go to stdout**, one line per event, `--log-format text|json`
  (`BROKER_LOG_FORMAT`, default `text` on a tty-less boot is still `text`; set
  `json` in any deployment with a collector). The broker does **not** ship logs
  anywhere itself: no HTTP appender, no syslog client, no OTLP log exporter. A
  service that holds credential custody should not also own an outbound network
  path that can block, retry, or be redirected.
- **An optional file sink** (`BROKER_LOG_FILE`) exists for deployments with no
  collector — systemd units, single-box installs, the demo. It is a convenience,
  not the recommended path.
- **Both sinks are non-blocking.** Writes go through a bounded queue drained by a
  dedicated thread (`tracing-appender`'s `non_blocking`). Under pressure the
  queue drops lines and says so. This is the load-bearing part: a `tracing::info!`
  on the `/authz` path must never perform a `write(2)`, and a full pipe on stdout
  must never become backpressure on the platform's request path.
- **Metrics are pull-based**: `GET /metrics`, Prometheus text 0.0.4, on the
  **internal listener** next to `/admin/*`. Pull, not push, for the same reason
  as logs — no egress. Hand-rolled from atomics rather than taking a metrics
  crate, following `infrastructure/query-cache` ADR-0015: the metric set is fixed,
  label cardinality is bounded by the router, and the exposition is a few dozen
  lines of string assembly.
- **Distributed tracing is out of scope** here. Event targets are named
  (`broker::http`, `broker::authz`, `broker::keepalive`, `broker::audit`) so
  spans can be added later without renaming anything.

### Plane 2 — Audit: durable, queryable, bounded window

A first-class table in the broker's own store, not a log stream. Specified in
[ADR-0015](ADR-0015-durable-audit-record-with-retention.md).

The two planes are connected in one direction only: **every audit event is also
emitted to the log stream** (target `broker::audit`, fail-open), so a SIEM gets
the long-term archive while the store keeps a queryable hot window. The reverse
is not true — most log lines are not audit events and never become rows.

### What each plane is responsible for, stated as a boundary

| Question | Plane |
|---|---|
| Is the broker slow? Which route? | metrics |
| Did that request get denied, and why? | logs |
| How many authz denials in the last hour? | metrics |
| **Who** revoked that API key, and when? | audit |
| Which backend exchanged a token for this user last Tuesday? | audit |
| Why did this custody go `dead`? | audit + logs |

The rule that keeps the hot path fast falls out of this table: **a request that
changes nothing produces no audit row.** A successful `/authz` check and a
successful `/session/refresh` are metrics, not history. This is not a
compromise for speed — it is what the audit record is *for*. Recording ten
thousand identical "yes" answers adds no accountability and destroys the
signal-to-noise of the record an investigator actually reads.

### Redaction is an invariant, not a convention

INV-12: no log line, audit row, or metric label may contain a session cookie
value, an upstream access or refresh token, a PKCE verifier, an OAuth `state` or
`nonce`, an API key secret, or a token hash. Permitted identifiers are `sid`,
`sub` (subject to the pseudonymisation knob in ADR-0015), `key_id`,
`custody_id`, `gen_no`, a **/24 or /48 client IP prefix**, and a user-agent hash.

This is enforced the way INV-5 was: by a test that runs the flows and greps the
captured output for known secret fixtures, not by review.

## Alternatives considered

- **One structured log stream, audit derived downstream by the SIEM.** Rejected.
  It makes the completeness of the security record depend on a sidecar's health
  and a collector's configuration, and it puts every audit question behind a tool
  the broker's own operator console cannot reach. It also loses the ordering and
  transactional guarantee that ADR-0015 gets for free.
- **Ship logs from the process (OTLP / HTTP appender).** Rejected: an outbound
  connection from the credential custodian that can block, buffer, or be pointed
  somewhere new is a worse liability than a lost debug line. The sidecar owns
  transport; the broker owns content.
- **Take a metrics crate (`metrics` + `metrics-exporter-prometheus`).**
  Rejected on the same grounds as ArrowRef's ADR-0015: a global recorder with its
  own locking for ~20 fixed series.
- **Audit every request including `/authz` and `/session/refresh`.** Rejected —
  see the boundary table. It would add a disk write to the platform's per-request
  path to produce a record no one can read.
- **A blocking stdout writer (the `tracing_subscriber::fmt` default).**
  Rejected once `/authz` became per-request: a slow or full stdout pipe would
  propagate into request latency across the whole platform.

## Consequences

- New workspace dependency: `tracing-appender` (tokio-rs). Taken for the
  non-blocking bounded writer, not for file rotation.
- `tracing-subscriber` gains the `reload` feature, which is what makes the
  runtime verbosity control in ADR-0015 possible.
- `/metrics` is unauthenticated on the internal listener, like ArrowRef's. It
  exposes counts and latencies, never identifiers. Network position is the
  control, as it already is for `/internal/token`.
- Operators get RED metrics per route per lane, saturation signals (audit queue
  depth, SSE subscribers, live generations) and durability health (audit drop
  counter — nonzero means the record has a hole, and it is alertable) from one
  scrape.
- Adding a new sink requires an ADR amendment stating its plane and its loss
  behaviour. There is no plugin surface for sinks and there will not be one
  (ADR-0005's posture, applied here).
