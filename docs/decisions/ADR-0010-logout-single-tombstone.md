# ADR-0010: Logout Is a Single Tombstone Killing All Generations Atomically; Upstream Revocation Is Best-Effort and Asynchronous

## Status

Accepted (2026-07-26)

## Context

A session can have up to `MAX_LIVE_GENS = 4` live generations at once
(ADR-0002). Logout must guarantee that none of them keep working, including
generations currently sitting in their grace window — a partial or racy logout
that leaves even one generation resolvable would silently undermine the whole
non-invalidating design's safety case. Upstream revocation (RFC 7009) is a
network call, which INV-8's reasoning against inline upstream I/O on hot paths
applies to just as much as it does to refresh.

## Decision

All generation tokens resolve through their single parent session record.
**`POST /logout` tombstones that one row in one write** (INV-7); every
generation, the meta cookie's validity, and the custody linkage die together
because no code path may validate a generation without first checking its
parent session is alive — the check is structural, not per-generation cleanup.
Tombstoned rows are retained for `grace` then reaped by the same sweep that
handles generation/session/txn expiry, so a request that was already in flight
gets a clean `401`, not a confusing not-found.

Upstream revocation is **enqueued best-effort and asynchronous** — the
endpoint does not await it. `/logout` always returns `200` (with an optional
`idp_logout_url` for the client to decide whether to navigate), even for an
already-dead session — idempotent by design.

## Alternatives considered

- **Invalidate each generation row individually on logout.** Rejected:
  multiple writes are not atomic — a crash or error partway through a
  per-generation loop leaves the session partially logged out, and every
  resource-check path would then need to inspect per-generation state instead
  of a single parent-liveness flag, which is both slower and a correctness
  hazard.
- **Synchronous upstream revocation before returning `200`.** Rejected for the
  same reason INV-8 rejects inline upstream calls on refresh: it puts network
  latency and upstream availability on a user-facing hot path, and upstream
  failure or slowness has no business blocking a *local* logout the user is
  actively waiting on.
- **Non-idempotent logout (error on an already-dead session).** Rejected:
  double-logout (e.g. a race between two tabs both triggering logout) is a
  normal case, not an error condition, and should not surface as one to the
  client.

## Consequences

- Local logout is guaranteed instant and total — this is the property the
  whole generation model depends on to be trustworthy (without it, ADR-0002's
  bounded exposure claim would be undermined by an unreliable kill switch).
- Upstream revocation can lag or silently fail without blocking or reversing
  the local tombstone — the upstream grant may remain technically live for a
  window after the user believes they are logged out locally. This is an
  accepted gap given the token never reaches the browser (ADR-0007), so a
  lagging upstream revocation is not itself a live local-session risk.
- The tombstone-then-reap-after-`grace` pattern (rather than immediate
  deletion) is shared machinery with generation expiry (ADR-0002) and with
  upstream-triggered kill (ADR-0011) — all three converge on the same "one
  atomic write, reaped later" mechanism, which is a deliberate simplification
  worth preserving if either is revisited.
