# session-broker

[![CI](https://github.com/jamiepearcey/session-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/jamiepearcey/session-broker/actions/workflows/ci.yml)

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

- `.github/` — CI and release pipelines

## Building it

Two build systems in one tree, deliberately independent — the broker serves no
UI assets, and the console talks to it over HTTP.

```sh
cd repo      && cargo test --workspace     # 148 tests; every invariant maps to one
cd repo/ui   && pnpm install && pnpm test  # the SDK's vitest suite
```

## Issuing tokens: create a principal, get a token

The broker can also sign tokens for machines and people so a product behind it can
verify them offline. It is **off** until you set both of these (one without the other
is a startup error); nothing else about the broker changes:

```sh
export BROKER_TOKEN_ISSUER=https://app.example.com   # your base_url, or a path under it
export BROKER_ISSUER_AUDIENCES=logless               # one audience per consumer product
```

The simple path for a machine is three steps. The admin calls go to the internal
listener (`internal_bind_addr`, `127.0.0.1:8090` by default) with the admin key; the
token call goes to the public listener.

```sh
# 1. Create a principal. The response carries its first secret, shown once.
curl -s -X POST http://127.0.0.1:8090/admin/principals \
  -H "Authorization: Bearer $BROKER_ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"edge-1","kind":"ingest","scopes":["ingest"],"audience":"logless"}'
# -> {"principal_id":"sp_…", …, "secret":{"secret_id":"sps_…","secret":"sbp_…", …}}

# 2. Paste principal_id and the secret into the machine's config. The secret does not
#    expire unless you said so; revoke it with DELETE /admin/principals/{id}/secrets/{secret_id}.

# 3. The machine trades them for a token (OAuth client credentials).
curl -s -X POST https://app.example.com/auth/token \
  -u "sp_…:sbp_…" -d grant_type=client_credentials
# -> {"access_token":"eyJ…","token_type":"Bearer","expires_in":86400,"scope":"ingest"}
```

`tenant` defaults to `default` and is created on first use; `indexes` defaults to
`["*"]`. The id and secret may also go in the form body as `client_id` and
`client_secret`. A token is a standard JWT (`alg=EdDSA`); its verification keys are at
`GET /auth/jwks.json`, and `docs/verifier/README.md` lists what a verifier checks.

For people, a signed-in user's browser calls `POST /session/token` with
`{"audience":"logless"}` (same origin, session cookie). On a single-tenant install that
needs no setup: a user with no grant gets the `default` tenant and the `viewer` role.
Give someone more with `POST /admin/user-grants`.

Things to know: an issued token cannot be revoked before it expires (revoking the
principal, secret or grant stops the next one); rotate the signing key with
`POST /admin/signing-keys/rotate` or `session-broker rotate-signing-key`; and the signing
keys live in the store, so back up the database and the keyfile together. The reasoning
and the list of what was deliberately left out are in
[ADR-0017](docs/decisions/ADR-0017-the-broker-as-a-token-issuer.md); the routes are in
[docs/openapi.yaml](docs/openapi.yaml).

## CI

`.github/workflows/ci.yml` runs on every push to `main` and every PR:

| Job | Gate |
|---|---|
| Rust | `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace` |
| MSRV | `cargo check` on 1.88, the version `Cargo.toml` claims |
| Advisories | `cargo audit --deny warnings`; exceptions live in `repo/.cargo/audit.toml` **with a stated reason** |
| UI | `pnpm typecheck`, `pnpm test`, `pnpm build` against a frozen lockfile |
| Contract | `redocly lint docs/openapi.yaml` — the spec is hand-written, so it can go invalid unnoticed |

The test job *is* the invariant check: every rule in
[.context/invariants.md](.context/invariants.md) maps to at least one test,
including INV-12 (no secret material anywhere in telemetry) and INV-13 (no
credential change without a committed audit row).

`.github/workflows/release.yml` builds linux x86_64 and aarch64 binaries plus the
console bundle on a `v*` tag, with checksums. It deliberately does **not** ship
`mock-idp`: that fixture can forge session state and must never sit next to the
real binary as a download.

Start with [docs/index.md](docs/index.md).
