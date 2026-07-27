# ADR-0007: Upstream Access Tokens Never Reach Browser JS — Proxy Lane for the Browser, Dual-Authenticated Exchange for Backends

## Status

Accepted (2026-07-26)

## Context

Token custody as a product surface (§1) only has value if the upstream access
token is genuinely never exposed to the browser's JS context — otherwise any
XSS on the app origin has direct access to the upstream API with the user's
full grant, which is exactly the exposure a custodian is supposed to remove.
Two different classes of consumer need the token: browser-initiated calls to
upstream APIs, and backend services calling on the user's behalf.

## Decision

Two separate lanes, neither of which puts the raw token in front of browser
JS:

- **`ANY /proxy/{upstream}/{*path}`** — the browser lane. Requires an ACTIVE
  session (cookie, `HttpOnly`) plus CSRF check on non-`GET` (INV-2). The
  broker strips cookies, injects `Authorization: Bearer <access_token>`, and
  forwards/streams. `Set-Cookie` is never passed through from upstream. This
  is the entire proxy feature — no rewriting, no caching (ADR-0001's scope
  boundary).
- **`POST /internal/token`** — the backend lane (INV-11). Requires **both** a
  static bearer key (broker↔backend trust, out-of-band provisioned) and a
  live session token in the body. Either alone yields nothing. Returns the
  current custodied access token; never triggers an inline upstream refresh
  (INV-8/ADR-0003).

## Alternatives considered

- **Return the upstream token to browser JS** for direct API calls. Rejected
  outright: this is the exact exposure the custody model exists to prevent —
  any XSS on the app origin would have the full upstream grant, not just the
  ability to drive the broker's fixed proxy surface.
- **A single exchange endpoint reachable directly from the browser.**
  Rejected: it would need either no dual-auth (weaker than INV-11) or would
  require the browser to hold the static API key, which just relocates the
  same secret into JS-reachable territory that this ADR exists to avoid.
- **JS-readable cookie carrying the upstream token.** Rejected: functionally
  identical exposure to returning it via `fetch` — any script on the origin
  can read it.

## Consequences

- **Stated residual risk: XSS on the app origin is not fully neutralized.**
  `HttpOnly` on the session cookie stops token *theft* — script cannot read
  the cookie value or the upstream token directly — but script running on the
  app origin can still *drive* the proxy lane, issuing requests as the user
  through `/proxy/*`, because the browser attaches the `HttpOnly` cookie
  automatically. An XSS payload can act as the user via the proxy for as long
  as the session lives; it cannot exfiltrate a reusable bearer token. This is
  a narrower blast radius than token exposure, not zero blast radius, and must
  not be described as "XSS-safe" without that qualifier.
- The proxy lane's minimalism (no rewriting/caching, per ADR-0001) is what
  keeps its own attack surface small — every additional feature added to it
  widens what a driven-via-XSS request can do.
- Backends need the static `broker_api_key` provisioned out of band; it is an
  operational secret whose compromise, combined with a live session token
  (itself already a compromise), yields the access token — dual auth means
  neither alone is sufficient, but both together is still the ceiling, not
  an impossible event.
