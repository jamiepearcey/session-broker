# session-broker Docs Index

## Start here for agents

Read these files before making changes:

- [docs/index.md](index.md)
- [.context/project-brief.md](../.context/project-brief.md)
- [.context/current-state.md](../.context/current-state.md)
- [.context/invariants.md](../.context/invariants.md)
- [docs/tasks/current.md](tasks/current.md)
- [Implementation strategy](architecture/implementation-strategy.md)
- [Observability & the audit record](architecture/observability.md) — event catalogue, metric catalogue, redaction rules, retention, and the sidecar/Prometheus recipes

## Decisions

- [ADR-0001: Session broker, not IdP — scope boundary and non-goals](decisions/ADR-0001-scope-boundary-and-non-goals.md)
- [ADR-0002: Non-invalidating generation rotation with bounded grace window](decisions/ADR-0002-non-invalidating-generation-rotation.md)
- [ADR-0003: Session lifetime decoupled from upstream tokens; refresh does no network I/O](decisions/ADR-0003-session-lifetime-decoupled-from-upstream.md)
- [ADR-0004: SameSite=Lax everywhere; Sec-Fetch/Origin is the actual CSRF boundary](decisions/ADR-0004-samesite-lax-and-csrf-boundary.md)
- [ADR-0005: Single storage surface — concrete SQL repo on SQLite, Postgres swap path](decisions/ADR-0005-single-storage-surface-sqlite-postgres.md)
- [ADR-0006: Opaque hashed cookie tokens; no JWT sessions; upstream tokens encrypted at rest](decisions/ADR-0006-opaque-hashed-cookie-tokens.md)
- [ADR-0007: Upstream access tokens never reach browser JS — proxy lane / dual-authenticated exchange](decisions/ADR-0007-upstream-tokens-never-reach-browser-js.md)
- [ADR-0008: Client coordination via held Web Lock only; server coalescing is the correctness backstop](decisions/ADR-0008-client-coordination-web-lock-only.md)
- [ADR-0009: Meta cookie is an unsigned, untrusted client hint](decisions/ADR-0009-meta-cookie-unsigned-hint.md)
- [ADR-0010: Logout is a single tombstone killing all generations atomically](decisions/ADR-0010-logout-single-tombstone.md)
- [ADR-0011: Upstream-revocation propagation policy (`kill` default) and custody health](decisions/ADR-0011-upstream-revocation-propagation-policy.md)
- [ADR-0012: Single-origin path-mounted deployment as the default topology](decisions/ADR-0012-single-origin-path-mounted-default.md)
- [ADR-0013: Session event stream (SSE) as a hint channel](decisions/ADR-0013-session-event-stream.md)
- [ADR-0014: Observability is two planes — lossy diagnostics and a durable audit record](decisions/ADR-0014-observability-two-planes.md)
- [ADR-0015: The audit record is a table in the broker's own store, kept for a bounded window and surfaced in the console](decisions/ADR-0015-durable-audit-record-with-retention.md)

## Context files

- [Project brief](../.context/project-brief.md)
- [Current state](../.context/current-state.md)
- [Invariants](../.context/invariants.md)

## Work queues

- [Current work](tasks/current.md)
