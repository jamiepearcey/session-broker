# ADR-0003: Session Lifetime Decoupled From Upstream Tokens; Refresh Does No Network I/O

## Status

Accepted (2026-07-26)

## Context

oauth2-proxy encrypts the upstream refresh token *into* the session cookie and
refreshes it synchronously, inline, on the request path. That couples every
session-refresh call's latency and reliability to the upstream IdP's
availability and RTT, and is a contributing factor in its documented
concurrent-refresh races. The product target for local refresh is p99 < 1 ms —
incompatible with any design that calls out to the IdP on that path.

## Decision

Session cookie lifetime is fully decoupled from upstream OIDC token lifetime.
`POST /session/refresh` performs **no network I/O, ever** (INV-8): it resolves
and rotates/coalesces purely against the in-memory session map. Upstream
liveness is read as a local flag (`custody.status: ok | degraded | dead`) set
by a separate subsystem.

A background keepalive worker (one tokio task, a `BinaryHeap` scheduler keyed
on `next_refresh_at`) independently keeps every upstream refresh-token grant
alive: `next_refresh = issued_at + 0.6 × access_token_lifetime`, jittered
±10% of the lead margin, with exponential backoff on transient failure and a
terminal `dead` state on `invalid_grant`. This runs entirely off the user
request path.

## Alternatives considered

- **Synchronous inline refresh on the session-refresh path** (oauth2-proxy's
  model). Rejected: puts upstream network latency and failure modes directly
  in the hot path and is the specific pattern implicated in known
  concurrent-refresh races.
- **On-demand upstream fetch only when a caller actually needs the access
  token** (lazy, no background worker). Rejected: pushes upstream latency onto
  whichever request happens to need the token first — typically the proxy
  lane or `/internal/token` — producing unpredictable latency spikes exactly
  where consumers expect a fast, already-fresh token; also creates a thundering
  herd if many sessions go stale simultaneously.
- **Poll upstream on a fixed global interval regardless of individual token
  lifetime.** Rejected: wastes calls for tokens with long lifetimes and risks
  under-refreshing tokens with short ones; a per-custody schedule sized to the
  actual `access_token_lifetime` is strictly better and not meaningfully more
  complex.

## Consequences

- The system now has two independent lifetimes to reason about — session
  idle/absolute expiry and custody health — rather than one. Every state-table
  entry (state machine, §3) has to account for both.
- A dead or degraded custody does not automatically end an ACTIVE session;
  only the propagation policy (`kill`/`degrade`, ADR-0011) decides what
  happens, and until it fires, sessions can be `ACTIVE` while the proxy lane
  and `/internal/token` return `upstream_revoked`-flavored errors. This is a
  deliberately confusing-looking split state, documented rather than hidden.
- A background scheduler, semaphore-bounded concurrency, and backoff/jitter
  logic are now permanent subsystems (`keepalive.rs`) with their own failure
  modes (crash-between-refresh-and-write is mitigated by write-through
  ordering on custody, not by the write-behind path used for sessions —
  see ADR-0005) — meaningfully more moving parts than a purely request-driven
  refresh model would have.
- The sub-millisecond refresh claim is real and testable (mock-IdP token-call
  counter proves zero upstream calls on the hot path) rather than aspirational.
