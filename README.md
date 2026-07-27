# session-broker

A small, self-hosted Rust service that sits between a browser SPA and an upstream
OAuth2/OIDC identity provider. It is **not** an identity provider. It is a
*session broker* and *token custodian*:

- The browser gets a plain session cookie (`HttpOnly`, `Secure`, `SameSite`) with
  a sliding lifetime, plus a JS-readable **meta cookie** carrying the non-secret
  expiry so a dumb client knows *when* to act without being able to read the secret.
- The broker holds the upstream OAuth refresh token server-side and keeps the
  access token alive in the background, ahead of expiry.
- **Session refresh never touches the upstream IdP on the hot path.** It is a
  local operation against local state.
- **Rotation does not invalidate the previous session cookie.** Generations
  overlap for a grace period, which removes the whole class of refresh races
  between concurrent requests and browser tabs.

## Why it exists

The field is either heavyweight identity platforms (Keycloak, Authentik, Zitadel,
Ory) or thin gatekeeping proxies (oauth2-proxy, Authelia, Tinyauth, Pocket ID).
Nothing in the middle implements non-invalidating rotation, a stateful background
keepalive worker, and a local-only fast refresh path. oauth2-proxy in particular
ties cookie refresh to upstream token refresh and has a history of concurrency
races during refresh.

The bet: put every hard guarantee on the server so the client SDK can be trivial.

## Layout

- `repo/` — implementation (Rust service + React client SDK and demo app)
- `docs/` — architecture, decisions (ADRs), threat model, task queue
- `.context/` — project memory read by agents before making changes

Start with [docs/index.md](docs/index.md).
