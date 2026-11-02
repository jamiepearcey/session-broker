# ADR-0019: Desktop sign-in handoff

Status: accepted (owner, 2026-11-01). Consumer: quant-workbench ADR-0152.

## Context

A desktop app signs its person in through the system browser (RFC 8252). The browser holds the broker session; the
app has neither that cookie jar nor a listener worth registering at the provider. It needs the broker's signed user
token, and it needs to hear why a sign-in failed, because nobody reads a browser tab for that.

## Decision

- The app makes a random verifier; the attempt id is `base64url(sha256(verifier))`. Nothing is registered with the
  broker in advance, so the broker holds nothing for an attempt nobody signed in for.
- The app opens `/auth/login?provider=<id>&return_to=/auth/desktop?attempt=<id>` (URL-encoded).
- `GET /auth/desktop?attempt=<id>` signs a user token for the session and holds it against the attempt for at most
  five minutes. It refuses (401) with no active session AND with a session that login did not create: the callback
  records which session the attempt's own login made. "Fresh" therefore means that login, not an age. A link cannot
  spend a session already sitting in the browser.
- `POST /admin/desktop-handoff {attempt, verifier}` on the admin lane answers 200 with one of:
  `{"status":"pending"}`, `{"status":"complete","access_token","expires_in","tenant","roles"}`,
  `{"status":"failed","error","detail","hint"}`. A finished answer is one use. A verifier that does not hash to the
  attempt is 403 `bad_verifier` and spends nothing. Expired looks like pending; the app holds its own deadline.
- A failure reaches the handoff as well as `/error`: an IdP error, a failed exchange, a refused `/auth/login`
  (`unknown_provider`, `provider_disabled`, ...), and a refusal at signing (`not_granted`). A callback with no txn
  cookie cannot name its attempt, so the app sees pending until its deadline.
- The audience is the install's only `issuer_audiences` entry; with several the handoff fails `lane_disabled`,
  because no body exists to choose one in. The tenant is `default_user_tenant` when set.
- All state is in memory, at most 64 attempts. A restart costs one retried sign-in.

The failure redirect keeps `error=oauth_error` beside the new `ref=`, which is the documented contract.

## Limits

The verifier ties an attempt to its app; the admin key ties the redeemer to the install. A person who learned an
attempt id and signed in first could end that attempt as themselves. The id appears only in that machine's browser,
for five minutes, and the app shows who came back.
