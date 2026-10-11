# ADR-0017: The broker becomes a token issuer — signed tokens for people and machines

## Status

Accepted (2026-10-11). **Amends ADR-0001** (the "not multi-tenant, no RBAC" boundary
moves, as described below) **and ADR-0006** (the "no JWKS surface" consequence stops
being true for issued tokens; session cookies stay opaque). Nothing else in the
session model changes: ADR-0002, 0003, 0007 and 0010 stand as written.

Design inputs, in order of authority: `docs/design/token-issuer-scope.md` (what was
built, with its addendum), then `docs/design/token-issuer.md` (the fuller design it
overrides where they differ). `docs/design/token-issuer-v2-pragmatic.md` is the
consultant's second pass; the scope file says which parts were adopted.

## Context

The broker already knows who a person is (an OIDC login) and holds the upstream
token for them. The products behind it (log-less first) need two more things that
no upstream IdP gives them in one place:

1. A **machine credential** for agents and services: something an operator creates
   once and pastes into config, which can be traded for a short-lived token the
   product can verify without calling anyone.
2. A **user token the product can verify offline**, carrying a tenant and roles,
   instead of an opaque upstream token that only the IdP understands.

The owner's steer was to be pragmatic and match what the market ships (Sentry,
Datadog, Splunk, Grafana, Elastic): long-lived keys pasted into config, OIDC
sign-on for people, standard JWTs. Auth must not become a pain and must not take
ingest down. So this ADR records a small feature and, deliberately, a list of
things that were not built.

## Decision

The broker issues **EdDSA (Ed25519) JWTs** and publishes the keys that verify them.
The feature is **off until `token_issuer` and `issuer_audiences` are both set**; off,
every new public route answers `501 lane_disabled`, no signing key is created, and
every existing route, body and test is unchanged.

### What exists

| Piece | Where | Notes |
|---|---|---|
| Signing keys | `signing_key` table; seed sealed under the custody keyring (AAD `signing:<kid>:seed`) | INV-5 applies to the seed. `kid` = base64url(SHA-256(public key)[..8]). State (pending, signing, published, retired, removed) is derived from `activate_at` / `retire_at` / `removed_at` against the clock; there is no state column. The boot reseal covers the seeds. |
| Key publication | `GET /auth/jwks.json`, `GET /.well-known/oauth-authorization-server` (public) | `Cache-Control: public, max-age=300, stale-if-error=2592000`, `ETag` with 304, `Date`. Pending keys are published, so verifiers learn a key before any token carries it. |
| Rotation | `POST /admin/signing-keys/rotate`, `session-broker rotate-signing-key [--now]` | An operation, never a schedule. Default publish lead is a day. Lead `0` is the emergency form (see limits). |
| Tenants, principals, secrets, user grants | `tenant`, `principal`, `principal_secret`, `user_grant` tables; `/admin/tenants`, `/admin/principals`, `/admin/user-grants` | Data on the admin lane. Every mutation is Tier A (INV-13). Naming a tenant slug creates it. |
| Machine tokens | `POST /auth/token` (public) | OAuth client credentials. Form body or HTTP Basic. All claims come from the principal's row. |
| User tokens | `POST /session/token` (public, cookie + INV-2) | Tenant, roles and indexes come only from `user_grant`. On a single-tenant install a user with no grant gets `default_user_tenant` with `default_user_roles`. |

Principal secrets are `sbp_` plus 32 random bytes (base64url) so secret scanners can
find them; only the SHA-256 is stored; the plaintext is shown once, at creation. They
have **no expiry unless the operator sets one**. Adding a secret leaves the older ones
valid until the operator revokes them (an optional `expire_old_in_secs` dates them).
Principals are in their own tables, never in `api_key`: nothing on `/internal/token`,
`/authz` or `/admin/*` can resolve a principal secret, and a test holds that.

Defaults (all `BROKER_*` config): machine tokens 86400 s, user tokens 3600 s (cut at the
session's idle expiry), per-principal maximum 30 days (allowed up to 365), key publish
lead 86400 s, JWKS `max-age` 300 s. One audience per consumer product (`logless` for the
agent, central and console alike); deployments are told apart by `iss`.

Verifiers follow `docs/verifier/README.md`: algorithm fixed to EdDSA before any key is
looked up, clock allowance 300 s either way, key set refreshed hourly and served from
cache without a time limit while the broker is unreachable. `docs/verifier/vectors.json`
holds test tokens generated from a fixed test-only seed by a test that fails if the
committed file drifts.

### Amendment to ADR-0001

ADR-0001 said the broker is "not an authorization engine" and "not multi-tenant". Both
survive in the sense the ADR meant them, and move in two precise ways:

- **Still true: no policy evaluation.** The broker *stamps* attested attributes
  (`tenant`, `kind`, `scopes`, `roles`, `indexes`) into a token. It does not interpret
  them, and it never decides whether a request is allowed. The resource server
  enforces. The broker validates only the grammar of scope and role words.
- **Changed: the broker now holds identity data of its own.** Tenants, service
  principals and user grants are rows in its store, administered on the admin lane and
  audited. This is "multi-tenant" only as a label on a token: one broker still serves
  one upstream IdP and one trust zone, and a tenant is a string that scopes what a
  consumer lets a token do, not an isolation boundary inside the broker.
- **Still true: not an IdP.** No passwords, no consent, no user store. People sign in
  upstream; the grant table only says what a signed-in subject may be stamped with.

### Amendment to ADR-0006

ADR-0006 chose opaque hashed cookie tokens over JWT sessions and noted that no JWKS
surface was needed. That choice stands for **sessions**: the cookie remains an opaque
256-bit value, the store holds only its hash, and nothing about rotation, grace or
logout changes. What changes is that the broker now publishes a JWKS because it signs a
*different* artifact: a short-lived, audience-bound token for a downstream product,
minted *from* a live session or a principal secret. A signed token is never accepted by
the broker as a session, and the cookie is never a JWT.

## Deliberately not built

Recorded so these are choices, not gaps. None of the vendors above ships them by default.

- Token introspection (`/internal/introspect`) and any per-request online check.
- Token exchange and down-scoping.
- A signed-token header on `/authz`.
- A `jti` replay cache.
- A per-principal issuance rate limit. (Wrong credentials are budgeted per client id;
  successful issuance is not limited.)
- Mandatory secret expiry, forced rotation schedules, or a required two-secret overlap.
- Refusing plaintext issuers. An `http://` issuer off loopback logs a warning at start;
  there is no `issuer_allow_plaintext` setting. (`base_url` itself is still refused
  off loopback over http by the existing rule.)
- Mapping tenant or roles from identity-provider group claims. The grant table is the
  source; nothing the IdP sends beyond `sub` is read.
- Per-tenant admin delegation in the console. One admin key, as before.
- Mutual TLS as a requirement anywhere.
- Opt-in `token_type: "broker"` on `/internal/token`. The first design had it; the scope
  addendum dropped it. `/internal/token` is unchanged and the console calls
  `POST /session/token`.

## Honest limits

- **An issued token cannot be revoked before it expires.** Revoking a principal, a
  secret or a grant stops *new* tokens at once; tokens already out live to their `exp`
  (a day for machines and an hour for people, by default). The controls are the TTL and
  the revocation of what mints them.
- **Losing the custody keyfile loses the signing keys** as well as the upstream tokens.
  The backup unit is still "database plus keyfile" (ADR-0016). Recovery from loss is a
  new key; every outstanding token fails at verifiers on their next key refresh.
- **Emergency rotation is not seamless.** A lead of zero makes the new key sign now and
  unpublishes every older key now. Outstanding tokens stop verifying, and verifiers
  reject newly issued tokens until their next refresh of the key set (up to an hour,
  unless they refresh on an unknown `kid`). That is the price of making a stolen key
  useless quickly, and the rotate response says so.
- **A verifier that has been offline for longer than the publish lead, across a rotation,
  can hold a stale key set.** The lead (a day) and the hourly refresh bound this; they do
  not remove it.
- **Principal secrets are long-lived bearer credentials.** That is the market norm and the
  point, and the reason they are prefixed, hashed, shown once, revocable at once and
  audited. A leaked one works until an operator revokes it.
- **`POST /session/token` is drivable by script on the app origin.** It is CSRF-guarded
  (INV-2) but script running on the SPA's origin can call it, the same residual ADR-0007
  states for `/session/refresh`. The audience binding and the hour-long lifetime are the
  mitigation.
- **The failure limiter is an existence oracle only for ids someone already has.** Ids
  that name no principal share one budget; once it is spent a made-up id gets 429 while
  a real id with a wrong secret still gets 401. Principal ids are 16 random characters,
  so this confirms an id a caller already holds, nothing more.
- **Single node.** Signing keys live in the one store; ADR-0005's Postgres/HA gap applies.

## Consequences

- **INV-12** gains permitted identifiers (`kid`, `jti`, `principal_id`, `secret_id`,
  tenant slug) and forbids principal secrets, signing seeds and issued tokens in any log
  line, audit row or metric label. Tests drive known fixture secrets through every new
  route and grep the captured output and the database file.
- **INV-13** widens "credential" to principal secrets, user grants, tenants and signing
  keys. Each mutation's audit row (`tenant.created`, `tenant.disabled`, `tenant.enabled`,
  `principal.created`, `principal.revoked`, `principal.secret_added`,
  `principal.secret_revoked`, `user_grant.created`, `user_grant.revoked`,
  `signing_key.created`, `signing_key.rotated`) commits in the same transaction.
  `signing_key.removed` is written at prune. Issuance is Tier B: `token.issued`
  (coalesced per principal or subject and audience) and `token.issuance_refused`.
- A new metric, `broker_tokens_issued_total{kind,outcome}`.
- `docs/openapi.yaml` gains an `issuer` tag, the new paths and schemas, and the
  `principalSecret` security scheme.
- `ed25519-dalek` becomes a direct dependency (it was already in the graph through
  `openidconnect`); `jsonwebtoken` is a dev-dependency only, so tests verify tokens with
  code that shares nothing with `issuer::jwt`. No RSA key exists, so the
  `RUSTSEC-2023-0071` ignore in `repo/.cargo/audit.toml` keeps its reason.
- Schema v5 adds five tables in one migration. There are no production deployments, so
  there is no upgrade shim.
- The console gains Principals, User grants and Signing keys views over the admin lane.
- Scope discipline: this widens ADR-0001's boundary once, deliberately. A request to add
  policy evaluation, introspection or IdP group mapping needs its own ADR.
