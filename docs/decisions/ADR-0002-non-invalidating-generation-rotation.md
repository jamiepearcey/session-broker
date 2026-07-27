# ADR-0002: Non-Invalidating Generation Rotation With Bounded Grace Window

## Status

Accepted (2026-07-26)

## Context

Standard rotating-token designs (including oauth2-proxy's) invalidate the prior
cookie the instant a new one is minted, and treat reuse of the old one as
proof of theft. That model races: a browser's cookie jar is shared across
tabs, and any two concurrent requests in flight when a rotation happens will
present the pre-rotation cookie. Under invalidate-on-rotate, the second request
loses — and depending on implementation, may log the whole session out. This is
the documented failure mode in oauth2-proxy under concurrent refresh. The
product's headline promise is that concurrent tabs/requests can never log each
other out (§1, non-negotiable in `.context/invariants.md`).

## Decision

Rotation is **non-invalidating within a bounded window**. Each session tracks
up to `MAX_LIVE_GENS = 4` generations (INV-6). Minting generation N+1 does not
kill generation N: N stays resource-valid until
`min(active_until, superseded_at + grace)`, `grace = 60 s` by default. A
30-second coalescing window collapses concurrent refreshes from multiple tabs
into re-issuing the same current generation rather than minting a storm of new
ones. The oldest generation is reaped once the cap is exceeded.

This deliberately gives up **reuse-after-rotation theft detection** — the
classical signal where using an old token after a new one exists proves theft.
What replaces it is **INV-6a**: every use of a non-newest generation is logged
with `(sid, gen, IP-prefix, UA-hash)`; use of a *reaped* generation, or
concurrent use of two generations from different IP-prefixes, emits a
`session.anomaly` event (metric, structured log, optional webhook). This is a
detection signal for operators to act on, not an automatic revocation — by
design, so that a false positive (e.g. a mobile network changing IP mid-grace)
never costs a legitimate user their session.

## Alternatives considered

- **Invalidate-on-rotate with reuse detection** (the standard pattern, and
  oauth2-proxy's). Rejected: this is precisely the race that produces
  concurrent-tab logout storms — the exact failure this project exists to
  avoid.
- **Per-session mutex serializing all requests through refresh.** Rejected:
  turns concurrent reads into a queue, defeating the sub-millisecond refresh
  target (INV-8/ADR-0003) and adding latency to every resource check, not just
  refresh.
- **Client-side coordination only** (elect one tab to refresh, others wait).
  Rejected as a *substitute* for server tolerance: even a correct leader-tab
  scheme cannot prevent in-flight requests from other tabs racing a rotation
  that happens mid-flight; the server has to tolerate the old token regardless.
  Client coordination is still used as an optimization (ADR-0008), not as the
  correctness mechanism.
- **No cap on live generations.** Rejected: unbounded generations under
  pathological rotate loops would grow the session row's working set without
  bound; `MAX_LIVE_GENS = 4` is sized to `⌈grace/coalesce⌉ + 2`, comfortably
  above what legitimate concurrent traffic produces.

## Consequences

- A stolen **current** cookie remains valid until the next rotation plus
  `grace`, or generation TTL — the same exposure window as any bearer cookie
  without rotation. Rotation here buys replay-window bounding and anomaly
  signal, not theft prevention.
- Operators must actually consume `session.anomaly` events for the design to
  pay off; unmonitored, it is a data collection exercise with no security
  effect. This is a known operational dependency, not a gap to be silently
  accepted.
- The non-invalidating property is also what makes memory-primary
  write-behind storage safe (ADR-0005): losing a just-minted generation on
  crash cannot log anyone out, because the superseded generation is still
  valid. The performance design downstream depends on this ADR holding.
- Every path that resolves a token must check the parent session's liveness,
  not just the generation's — otherwise a tombstoned session's still-in-grace
  generations would incorrectly resolve (see ADR-0010, INV-7).
