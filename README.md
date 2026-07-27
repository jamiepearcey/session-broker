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
