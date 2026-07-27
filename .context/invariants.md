# Invariants

Canonical list. Rationale, threat model, and adversary set live in
[docs/architecture/implementation-strategy.md §2](../docs/architecture/implementation-strategy.md).
Every invariant maps to at least one test. Do not break one to make a test pass.

- **INV-1** Session cookie is `__Host-`-prefixed: `Secure; HttpOnly; Path=/; SameSite=Lax`, no `Domain`.
- **INV-2** Every state-mutating cookie-authenticated endpoint enforces `Sec-Fetch-Site: same-origin`, falling back to `Origin` equality; failures are `403 csrf_rejected` before any state is touched.
- **INV-3** Every login attempt has a server-side, single-use, 10-minute txn holding `state`/PKCE verifier/`nonce`/`return_to`; the browser holds only an opaque txn id. Callback validates all of them plus the ID token.
- **INV-4** `return_to` is a same-origin absolute path only, validated at login-start and re-validated at callback. The IdP redirect URI is static config, never request-derived.
- **INV-5** Cookie values are 256-bit CSPRNG tokens; the store holds only `SHA-256(token)`. Upstream tokens are encrypted at rest and never appear in a browser-reachable response.
- **INV-6** Non-invalidating rotation is bounded: ≤ `MAX_LIVE_GENS` (4) live generations per session; a superseded generation is valid only for `grace` (60 s) after its successor was minted.
- **INV-6a** Use of a non-newest generation is logged; use of a reaped generation, or of two generations from different IP-prefixes concurrently, emits a `session.anomaly` event. Signal, not revocation.
- **INV-7** Logout tombstones the single session record in one write; every generation dies atomically with it. No path validates a generation without checking its parent session is alive.
- **INV-8** `/session/refresh` performs no network I/O, ever. Upstream health is read as a local flag.
- **INV-9** The server never reads `broker_meta`. It is an unsigned, non-secret client hint.
- **INV-10** Default topology is single-origin path-mount; no CORS surface exists unless subdomain mode is explicitly enabled.
- **INV-11** `/internal/token` requires both the static broker API key and a live session token; either alone yields nothing.

## Non-negotiables of the design

- Issuing a new session cookie **never** invalidates the previous one inside the grace window. This is the product; everything else bends around it.
- The refresh hot path never calls the upstream IdP.
- Guarantees live server-side so the client SDK stays trivial. If a client-side fix is being considered for a correctness problem, the fix belongs on the server instead.
