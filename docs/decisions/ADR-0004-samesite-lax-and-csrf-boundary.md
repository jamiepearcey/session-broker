# ADR-0004: SameSite=Lax Everywhere; Sec-Fetch/Origin Is the Actual CSRF Boundary

## Status

Accepted (2026-07-26)

## Context

The OAuth callback is a cross-site top-level `GET` navigation initiated by the
IdP redirecting back to the app. The transient txn cookie (`__Host-broker_txn`,
INV-3) must survive that navigation to complete login — but `SameSite=Strict`
cookies are stripped on cross-site top-level navigation, which would break
every login. `Strict` on the session cookie specifically would additionally
break top-level navigation into the proxy lane or any future SSR path, for no
compensating benefit, because CSRF protection cannot be allowed to rest on
`SameSite` alone regardless (browser SameSite defaults and behavior have
historically varied and are not a security boundary contract).

## Decision

**`SameSite=Lax` on every cookie the broker sets** (INV-1), with CSRF
protection implemented independently: every state-mutating cookie-authenticated
endpoint (`POST /session/refresh`, `/logout`, non-GET proxy-lane calls)
requires `Sec-Fetch-Site: same-origin` (or `none` for explicitly allowed direct
navigation), falling back to `Origin` header equality when `Sec-Fetch-*` is
absent (INV-2). Failure is `403 csrf_rejected` before any state is touched.

The one endpoint that mutates state under a cross-site-reachable `GET` is
`GET /session/refresh?interactive=1` — a top-level navigation form. It is
treated as an exception: it issues a cookie to whoever holds the legitimate
cookie already (it cannot create a session for an attacker or a third party),
so it is not CSRF-exploitable in the conventional sense — it just extends
session life.

## Alternatives considered

- **`SameSite=Strict` on the session cookie.** Rejected: breaks the OAuth
  callback's txn cookie and any top-level navigation into the proxy lane or a
  future SSR path, while adding no CSRF protection beyond what `Lax` + the
  explicit guard already provides, since the guard doesn't rely on `SameSite`
  in the first place.
- **Rely on `SameSite=Lax` alone as the CSRF defense, skip the explicit
  guard.** Rejected: `Lax` still allows top-level cross-site `GET` navigations
  to carry the cookie, and CSRF protection must not depend on browser cookie
  policy correctness across all supported browsers and versions — an explicit,
  testable server-side check is required regardless of `SameSite` value.
- **`SameSite=None` with an explicit CSRF token (double-submit or similar).**
  Rejected: adds a token-management surface (mint, thread through client,
  compare) that `Sec-Fetch-Site`/`Origin` checking makes unnecessary, and
  `None` requires the cookie to travel on every cross-site request, which is
  more exposure than needed for a same-origin-by-default deployment (INV-10).

## Consequences

- **Accepted residual risk, stated explicitly:** a cross-site page can force a
  victim's browser into a top-level navigation to
  `GET /session/refresh?interactive=1&return_to=...`, and because that request
  carries the `Lax` session cookie, it can *extend* an already-live session
  (slide idle expiry, rotate a generation) without the victim's awareness. It
  cannot create a session, cannot read tokens, and cannot make the broker
  perform any effect beyond issuing a cookie to the legitimate holder — but
  session-extension-by-forced-navigation is a real, accepted trade, not an
  oversight.
- Every new state-mutating endpoint added later must implement the INV-2 guard
  explicitly — it is a coding discipline requirement enforced by the guard
  module (`http/guards.rs`) and by tests, not something `SameSite` gives for
  free.
- Browsers/clients without `Sec-Fetch-*` support fall back to `Origin`
  equality, which is still a solid check, but is a second code path that needs
  its own negative tests.
