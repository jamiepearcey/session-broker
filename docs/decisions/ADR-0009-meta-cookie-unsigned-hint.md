# ADR-0009: Meta Cookie Is an Unsigned, Untrusted Client Hint — the Server Never Reads It

## Status

Accepted (2026-07-26)

## Context

The client needs to know *when* to act (show a UI state, decide whether to
call refresh proactively) without round-tripping to the server on every
render, in keeping with the "server-smart, client-dumb" ethos (§1). Something
JS-readable has to carry that information. The risk is scope creep: once a
client-readable cookie exists, it is tempting to eventually also read it
server-side as a shortcut (e.g. to skip a lookup) — which would make it a
second, unauthenticated input channel into a security-sensitive decision.

## Decision

`broker_meta` is a `Secure; Path=/; SameSite=Lax` (JS-readable, **not**
`HttpOnly`) cookie carrying a decoded snapshot (`sub`, `sid` prefix, `gen`,
`active_until`, `refresh_until`, `absolute_until`, `custody`). It is
**unsigned and non-secret** (INV-9). **The server never reads it, on any code
path.** The client uses it only for UX timing and treats server `401`
responses as ground truth whenever they disagree with what the cookie implies.

## Alternatives considered

- **Sign the meta cookie (HMAC)** so the server *could* optionally trust it
  later. Rejected: the payload's only legitimate use is client-side UX
  timing, never authorization — signing buys nothing for that use case and
  creates both a key-management surface and a standing temptation for a
  future contributor to treat a "signed, therefore trustworthy" cookie as an
  input to a real decision, which is exactly the failure mode INV-9 exists to
  prevent.
- **Drop the meta cookie; have the client always call `GET /session` to check
  status.** Rejected: adds a network round trip to every session-status check
  the client wants to make (e.g. rendering a status badge, deciding whether to
  schedule a refresh), working against the fast, mostly-local client model —
  the meta cookie is a synchronous, zero-latency read of `document.cookie`
  instead.

## Consequences

- A malicious or buggy client can fabricate, freeze, or delete its own
  `broker_meta` payload arbitrarily — this is harmless by construction, since
  no server-side code path consumes it. The worst outcome is a stale UI badge
  or a spurious client-initiated refresh call, which the server would then
  correctly resolve (coalesce or reject) on its own terms.
- Any future PR that reads `broker_meta` server-side — even as a claimed
  performance shortcut — violates INV-9 and must be rejected in review; this
  ADR is the recorded rationale for that rejection.
- The client can be arbitrarily wrong about session state (e.g. after clock
  skew, after manual cookie editing) without any server-side security
  consequence, because every consequential action still resolves through an
  authenticated store lookup.
