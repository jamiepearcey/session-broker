# ADR-0008: Client Coordination via Held Web Lock Only; Server Coalescing Is the Correctness Backstop

## Status

Accepted (2026-07-26)

## Context

Multiple browser tabs share one cookie jar and, left uncoordinated, would each
run an independent refresh timer, producing redundant `/session/refresh`
calls. The client is meant to stay "dumb" (§1): it needs a lightweight way to
elect one tab to own the timer, without taking on cross-tab messaging
infrastructure — because server-side refresh coalescing (ADR-0002's 30-second
window) already makes redundant refreshes harmless, not just tolerable.

## Decision

Leader election uses **`navigator.locks.request('broker-refresh-leader', ...)`
only**. The tab holding the lock runs the refresh timer; others don't, but all
tabs still do a lazy check on `visibilitychange`/`focus`/`online` regardless of
leadership. Where Web Locks are unavailable (pre-2022 browsers), the fallback
is **every tab runs the timer** — no polyfill, no alternative coordination
channel — because server-side coalescing absorbs the redundancy.

The following coordination mechanisms were considered and explicitly rejected,
each for a concrete disqualifying reason:

- **SharedWorker.** Not supported on Chrome for Android — a shipping,
  non-negligible client target — which alone rules it out as the primary
  mechanism.
- **Service Worker + Periodic Background Sync.** Chrome-only, permission-
  gated (users can deny it, silently degrading the feature), and its timing
  is imprecise/best-effort by design — wrong tool for a foreground refresh
  timer that needs to fire close to `active_until − skew`.
- **BroadcastChannel.** Once the server tolerates redundant refreshes
  (coalescing), a same-origin messaging channel to prevent redundant refresh
  *calls* buys nothing beyond what letting every tab call and having the
  server collapse them already achieves — it is coordination code solving a
  problem the server already solved.

## Alternatives considered

(Beyond the three above, evaluated as the primary mechanism itself.)

- **No client-side coordination at all — every tab always runs its own
  timer.** Rejected as the *primary* design, though it is the honest fallback:
  without any leader signal, every tab-focus/timer-fire produces a refresh
  call; server coalescing still makes this correct, but it is needlessly
  chatty when a near-universal, cheap leader mechanism (Web Locks) is
  available.

## Consequences

- Correctness of the whole client **never depends on leader election being
  right** — it is purely an optimization to reduce redundant calls. This is
  only true because ADR-0002/ADR-0003 built the server-side coalescing
  backstop first; this ADR is downstream of those, not independent of them.
- Pre-2022 browsers get more network chatter (every tab times its own
  refresh) but no correctness degradation — an accepted, not hidden, cost.
- Leader handoff on tab close has no explicit signal beyond lock release; the
  next lock acquirer simply starts running the timer. There is no "election
  event" the app can hook into beyond the `held` flag — this keeps the client
  small (~300 lines total) at the cost of no visibility into *why* leadership
  moved.
- If a future browser regression or bug ever causes Web Locks to silently
  fail to release, multiple tabs could believe they hold the lock
  simultaneously; this degrades to the "every tab times its own refresh"
  case, not a correctness break, because of the same server backstop.
