# ADR-0013: Session event stream (SSE) as a hint channel

Status: Accepted (2026-07-27)

## Context

A session can die without the browser doing anything: another tab logs out, an
administrator revokes it, or the upstream grant is revoked and the keepalive
worker tombstones every session behind it (ADR-0011). Today the client only
finds out on its next request or lazy check — correct, because the 401 is the
enforcement (INV-7), but possibly a minute late. For a product whose entire
point is session correctness, "logged out somewhere else, still looks signed in
here" is a poor showing.

The obvious instinct is to have the server push a *new cookie state* down. That
is not possible, and the reason shapes this whole decision.

## Decision

Add `GET /session/events`, a cookie-authenticated `text/event-stream` carrying:

- `session.killed` — `{"sid", "reason"}` where reason is `logged_out` |
  `upstream_revoked` | `admin_revoked`
- `custody.changed` — `{"sid", "custody"}` where custody is `ok` | `degraded` | `dead`

plus `: keepalive` comments every 20s and an initial `retry: 5000`.

**The stream carries no session material and sets no cookies.** `Set-Cookie` is
a response header, flushed once when the stream opens; a browser will never read
cookie material out of the event body, and trailers are not processed by
browsers either. Cookies therefore continue to ride ordinary request/responses.
For the logout case there is nothing to write anyway — the session is tombstoned
server-side, so the cookie still sitting in the browser is already inert.

**Events are announced from inside `SessionMap`, not from handlers.** A
`SessionObserver` is installed once at boot; `tombstone_session*` and
`set_custody_status` publish. There is exactly one path that kills a session and
one that announces it, so a future caller cannot forget to.

**The stream is a hint, never enforcement** (INV-9's principle, applied to a
second channel). A disconnected, backgrounded or lagging client may miss events;
the 401 on the next request remains the mechanism that ends a session. A client
that never receives an event is never *wrong*, only late.

## Alternatives considered

- **Deliver a refreshed cookie over the stream.** Impossible per above. The one
  workaround — end the stream so `EventSource` reconnects, and put `Set-Cookie`
  on the reconnect's initial response — was rejected: it recouples cookie
  lifetime to stream lifetime, which is exactly the coupling ADR-0003 removes.
- **WebSocket.** Bidirectional, and we have nothing to send upstream. SSE
  reconnects on its own, survives proxies as plain HTTP, and needs no new
  framing.
- **Polling.** Already exists in effect (the refresh timer), and is what this
  optimises away for the idle-tab case.
- **Per-session broadcast channels.** A map of channels in `SessionMap` buys
  nothing at this scale over one broadcast plus a per-subscriber predicate, and
  costs subscriber bookkeeping in the hot data structure.

## Consequences

- A revoked session reaches a connected client in milliseconds rather than at
  its next lazy check. Verified live: a logout issued on one connection surfaced
  on an open stream immediately.
- **Connection budget is now a client-side concern.** One stream occupies one
  HTTP/1.1 connection and browsers allow six per origin, so a per-tab stream
  starves the pool at six tabs. Over HTTP/2 (~100 multiplexed streams) per-tab
  is fine. Browsers only negotiate h2 over TLS, so which regime applies is
  decided by deployment, not by the app. The SDK therefore exposes
  `events: 'leader-only' | 'per-tab' | 'off'` defaulting to `leader-only` — safe
  under both, at the cost of non-leader tabs falling back to the lazy path.
- **`EventSource` reconnects forever by default**, and this endpoint 401s once a
  session is dead. A naive client would hammer the broker exactly as the
  pre-existing refresh hot-loop bug did. The SDK must halt on a terminal
  condition; this is a client-side obligation created by this ADR.
- Slow subscribers are dropped after 64 queued events rather than being allowed
  to grow unboundedly. Nothing is lost that matters — the next request still
  tells the truth.
- Idle streams hold server resources. They are cheap in async Rust (a task and a
  broadcast receiver each), so the ceiling is the browser's connection budget,
  not the broker's.

## Related

- INV-7 (logout kills every generation), INV-9 (hints are never inputs),
  INV-2 (the stream is same-origin-checked; `EventSource` cannot set headers,
  so the guard leans on `Sec-Fetch-Site`, which script cannot forge)
- [ADR-0003](ADR-0003-session-lifetime-decoupled-from-upstream.md),
  [ADR-0008](ADR-0008-client-coordination-web-lock-only.md),
  [ADR-0010](ADR-0010-logout-single-tombstone.md),
  [ADR-0011](ADR-0011-upstream-revocation-propagation-policy.md)
