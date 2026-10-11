<!-- Consultant's second pass, written after the owner's 'be pragmatic' steer. Reference only: token-issuer-scope.md says which parts are adopted. -->

# session-broker as token issuer for people and machines — design

Posture (owner steer applied): match Sentry/Datadog/Grafana/Elastic — long-lived pasted keys for machines, OIDC SSO for people, plain JWTs where offline verification is needed. Each item carries a "market" clause. Scope is cut to 5 slices.

## 1. Token format
**Recommend:** JWT, compact JWS, `alg: "EdDSA"` (Ed25519), header `{alg, kid, typ:"JWT"}`. Claims: `iss` (broker `base_url`), `sub` (principal_id for machines, IdP `sub` for people), `aud` (one string), `exp`, `iat`, `jti` (16 random bytes b64url), `tenant`, `kind` (`ingest|node|replica|reader|admin|user`), `scopes` (array), `indexes` (array; `["*"]` = all of the tenant's), `roles` (array, user tokens only), `sid` (user tokens only). No `nbf` (skew rule covers it). Size: ≤ 1 KiB typical; refuse a principal with > 64 indexes rather than mint a 4 KiB token. Clock skew: verifiers accept 300 s on `exp`/`iat` (Auth0/AWS/Google default).
**Crates:** `ed25519-dalek 2.2` as a *direct* dependency — it is already in the broker's graph through `openidconnect` (Cargo.lock 1491-1519), so zero new transitive code; generate seeds with `token::fill_random` (crates/session-broker/src/token.rs:31), `SigningKey::from_bytes`. Hand-roll the ~40-line compact-JWS encoder with `serde_json` + `base64` (both present). Dev-dependency `jsonwebtoken` (workspace dep already, mock-idp uses it) as the *independent* verifier in tests. No RSA: update the ignore comment in `repo/.cargo/audit.toml` ("the broker ever gains a private key of its own" → "an RSA private key"), reason stays true.
**Rejected:** ES256 (P-256 needs DER/raw signature conversion and is one footgun richer; EdDSA is what Envoy/Istio/`ring` verify natively); PASETO (not what consumer libraries speak; new crate).
**Market:** JWT + JWKS is universal; EdDSA is supported by every current verifier library.
**Unverified:** `jsonwebtoken` 11's EdDSA/JWK API names (`DecodingKey::from_ed_components`, `jwk` module) — registry sources are not extracted locally; `cargo tree` is impossible offline. Implementer confirms before S1.

## 2. Signing keyring
**Recommend:** a second keyfile `session-broker.signing.key` (default beside the DB; config `signing_keyfile_path`), same text format as the custody keyring with magic `session-broker-signing-keyring v1`, lines `id b64url(seed32) status since_epoch`, status ∈ `next|active|retired`. Reuse `KeyRing::parse/render/write_atomically/refuse_permissive` from crates/session-broker/src/store/crypto.rs:158-313 by parameterising the magic and adding the two trailing fields; do **not** put Ed25519 seeds in the custody ring (two "active" semantics in one file, and `rotate-key` would rotate both). `kid` = first 8 bytes of SHA-256(public key), b64url — self-identifying, survives a restore (a counter-derived kid would collide with a previously published key after a backup restore).
**Operations (CLI, broker stopped, like `rotate-key` at main.rs:427-456):** `signing-key add` (new key, status `next`, published in JWKS, not signing), `signing-key activate <kid>` (becomes signer; previous active → stays published), `signing-key retire <kid>` (removed from JWKS; refused while `since + machine_token_max_ttl_secs > now` unless `--force`), `signing-key list`. **None is a duty**: a deployment can run one key forever. Boot with the feature enabled and no file: generate one `active` key, log loudly, like `create_keyfile` (crypto.rs:280). Boot with the feature disabled: no file is created or read.
**HA/restore:** nothing in SQLite depends on the signing key; back up keyfile and DB together (ADR-0016 posture). Losing the file = every outstanding token fails at verifiers on their next JWKS refresh; recovery is a new key.
**INV-5/INV-12:** the seed lives only in the 0600 file and process memory; `Debug` redacts (crypto.rs:63 pattern); JWKS exposes only `x`. `kid` and public key are permitted identifiers.
**Rejected:** admin HTTP route that rotates (a browser tool holding the admin key must not write key material; same line ADR-0015 draws for sinks).
**Market:** one long-lived key, manual rotation with publish-before-use (Keycloak, Okta "next key", Ory).

## 3. Publication, TTLs, revocation
**Routes (public listener; JWKS is public data and verifiers sit outside the internal network):** `GET /.well-known/openid-configuration` (`issuer`, `jwks_uri`, `token_endpoint`, `id_token_signing_alg_values_supported:["EdDSA"]`, `grant_types_supported:["client_credentials"]`) and `GET /.well-known/jwks.json` (`{"keys":[{kty:"OKP",crv:"Ed25519",kid,use:"sig",alg:"EdDSA",x}]}`, `next` and `active` keys only). Headers: `Cache-Control: public, max-age=300, stale-if-error=2592000`, `ETag` = sha256(body) → 304 on `If-None-Match`. Handlers set Cache-Control explicitly because `http::hardening::security_headers` defaults to `no-store` (hardening.rs:93). Both answer 501 `lane_disabled` when the issuer is off.
**TTLs:** machine default 24 h (`machine_token_ttl_secs`), per-principal `max_ttl_secs` default 30 d, allowed up to 365 d (an operator who wants "mint once, paste forever" can). User tokens 1 h (`user_token_ttl_secs`), capped at the session's `absolute_exp`. Verifier trusts cached keys for **30 days** without reaching the broker; refreshes hourly when it can.
**Revocation, honestly:** an offline-verified token is valid until `exp`. Revoking a principal stops re-issuance; the blast window is the token TTL. Emergency: `signing-key retire` kills everything within one verifier refresh. No introspection route, no revocation list (cut; see §13).
**Market:** Datadog/Splunk HEC keys never expire and are checked online by the vendor; for offline edge verification the norm is Envoy/Istio JWT with a JWKS cache of 5 min–24 h and a long `stale-if-error`.

## 4. Service principals as data (schema v5)
**Recommend:** new tables, not `api_key`. `api_key` is the credential that resolves any user's session on `/internal/token` and `/authz`; an ingest key must never be that. Three tables in ONE migration (`store/mod.rs` `MIGRATIONS`, bump `SCHEMA_VERSION` to 5):
```sql
CREATE TABLE principal (
  principal_id TEXT PRIMARY KEY,   -- "sp_" + 16 chars, public
  name TEXT NOT NULL, tenant TEXT NOT NULL,
  kind TEXT NOT NULL,              -- ingest|node|replica|reader|admin
  scopes TEXT NOT NULL,            -- JSON array
  indexes TEXT NOT NULL,           -- JSON array, ["*"] = all
  audience TEXT NOT NULL, max_ttl_secs INTEGER NOT NULL,
  created_at INTEGER NOT NULL, created_by TEXT, last_used_at INTEGER, revoked_at INTEGER);
CREATE TABLE principal_secret (
  secret_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principal(principal_id),
  secret_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE INDEX principal_secret_live ON principal_secret(secret_hash) WHERE revoked_at IS NULL;
CREATE TABLE user_grant (
  sub TEXT NOT NULL, tenant TEXT NOT NULL, roles TEXT NOT NULL, indexes TEXT NOT NULL,
  created_at INTEGER NOT NULL, created_by TEXT, revoked_at INTEGER, PRIMARY KEY (sub, tenant));
```
Secret: `sbp_` + 43-char `oauth::random_id()` (prefix for secret scanners, as `ghp_`/`glsa_`), SHA-256 at rest (256-bit random needs no stretching — same reasoning as `api_key.key_hash`), shown once. A principal may hold several live secrets (add → swap config → revoke old); overlap is optional, never required. Tenant: a free-form slug `^[a-z0-9][a-z0-9-]{0,62}$`, no tenant table (self-host uses `default`, owner decision 1); a tenant exists iff something names it. Rejected: tenant table with disable/quota — that is log-less's data, not the broker's.
**Admin routes (internal listener, admin key, `authorised()` admin.rs:108):** `GET|POST /admin/principals`, `GET|PUT|DELETE /admin/principals/{id}` (DELETE = revoke, 404 on second), `POST /admin/principals/{id}/secrets` (new secret, shown once), `DELETE /admin/principals/{id}/secrets/{secret_id}`, `GET|POST /admin/user-grants`, `DELETE /admin/user-grants/{sub}/{tenant}`, `GET /admin/signing-keys` (read-only). New `AdminWrite` variants: `InsertPrincipal`, `UpdatePrincipal`, `RevokePrincipal`, `InsertPrincipalSecret`, `RevokePrincipalSecret`, `TouchPrincipal`, `InsertUserGrant`, `RevokeUserGrant` (writer.rs:90-106).
**Defect-shape warnings:** (a) every new `AdminWrite` variant is "handled but never sent" until its route exists — S2's table-driven test drives each route and asserts the matching audit action; (b) the live-secret lookup predicate must join BOTH `principal_secret.revoked_at IS NULL AND principal.revoked_at IS NULL` — a test revokes the principal while the secret row is live and expects refusal; (c) `TouchPrincipal` mirrors `enqueue_touch` (writer.rs:264) and had better be sent from `/token` — test asserts `last_used_at` moves.
**Market:** Grafana service accounts + tokens, Elastic API keys, Datadog API/app keys: named, long-lived, hashed, revocable, second key for rotation.

## 5. Issuance endpoints
**(a) Machines — `POST /token`, public listener,** RFC 6749 client-credentials: `application/x-www-form-urlencoded` `grant_type=client_credentials&client_id=<principal_id>&client_secret=<secret>[&ttl=<secs>]`, or HTTP Basic. JSON bodies rejected (`invalid_request`) — every OAuth client library speaks form. Response `{access_token, token_type:"Bearer", expires_in}`. Refusals: 400 `invalid_request`, 401 `invalid_client` (unknown/wrong/revoked secret; rate-limited bucket `token_auth` via `guards::RateLimit`, peer-keyed, failures only), 401 `unauthorized_client` (principal revoked), 400 `invalid_request` for `ttl > max_ttl_secs`, 501 `lane_disabled`. Claims come only from the row: `tenant`, `kind`, `scopes`, `indexes`, `aud` — a `tenant=` or `aud=` form field is ignored. Successful issuance is not rate-limited beyond the public login limiter rule (only when `rate_limit_client_ip_header` is set, main.rs:206-221); cost is one hash lookup + one Ed25519 sign.
**(b) People — `POST /session/token`, public listener,** cookie + INV-2 CSRF (`guards::require_same_origin`), body `{"aud":"logless","tenant":"acme"}` (`tenant` optional when the user has exactly one grant). Resolution: `Resolution::Active` only (same bar as `/internal/token`, internal.rs:392-399). Grant lookup in `user_grant`; if none and `default_user_tenant` is set, synthesize `{tenant: default, roles: default_user_roles, indexes:["*"]}` so self-host needs no admin step. Token: `sub`, `sid`, `tenant`, `roles`, `indexes`, `kind:"user"`, `exp = min(now+1h, absolute_exp)`. Refusals: `invalid_session`/`session_expired` (existing codes, error.rs:13), 403 `no_grant`, 400 `unknown_audience`, 501 `lane_disabled`. `/internal/token` and `/authz` are untouched and stay the platform's lanes; the log-less console simply calls `/session/token` and carries the JWT to an agent or exchanges it for S3 credentials.
**Tenant/roles source:** broker-side `user_grant` table (Sentry/Datadog model: membership is the product's data), with the self-host default rule. IdP group→tenant mapping deferred: the callback keeps only `sub` today (oauth.rs:407, `UpstreamTokens` oauth.rs:126), so mapping would first require retaining claims; recorded as v2.
**(c) Exchange/down-scoping:** cut.
**Market:** client_credentials form POST is what every vendor's machine auth is; user access tokens from a signed-in session are what Grafana/Sentry consoles do internally.

## 6. Audience model
One audience string per consumer *product*, listed in config `token_audiences` (e.g. `logless`); `principal.audience` must be in it; user tokens request one from it. Agents, central and console of one log-less deployment share `aud=logless`; different deployments are told apart by `iss` (each broker's `base_url`). Existing platform services never see a JWT unless they later add their own audience. Rejected: per-component audiences (agent/central/console) — a matrix nobody ships. **Market:** Auth0 "API identifier", one per API.

## 7. Audit and metrics
Tier A (rides `Command::Admin`, same transaction): `principal.created`, `principal.updated`, `principal.revoked`, `principal.secret_added`, `principal.secret_revoked`, `user_grant.created`, `user_grant.revoked`. Tier B: `token.issued` (actor `backend` with `actor_id=principal_id`, or `user` with `sub`; coalesced per `(actor_id, aud)` per `audit_coalesce_secs` by generalising `should_record_exchange` audit.rs:376 to a `(String,String)` key), `token.issue_refused` (never coalesced, `reason` = refusal code), `signing_key.activated|retired` (emitted at boot by diffing the file's statuses against the previous boot's kids recorded in `detail`; `system` actor). `detail` carries `{aud, kind, exp, jti, kid}`. INV-12: add `jti`, `principal_id`, `kid` to the permitted list; the token, the secret and `secret_hash` are forbidden. Metrics: `broker_tokens_issued_total{kind,outcome}` and gauge `broker_signing_key_age_seconds` (alert > 1 y is advisory). **Market:** vendors audit key create/revoke; nobody audits every token mint.

## 8. Compatibility and config
Off until `token_audiences` is non-empty; then `token_issuer` defaults to `base_url`. All new routes answer 501 `lane_disabled` when off (mounted always, like the admin lane, so tests cover both states). No existing route, cookie, SDK call, or `/internal/token`/`/authz` behaviour changes. New config (defaults): `token_audiences` (empty), `token_issuer` (base_url), `signing_keyfile_path` (`session-broker.signing.key`), `machine_token_ttl_secs` 86400, `machine_token_max_ttl_secs` 2592000 (hard ceiling 31536000), `user_token_ttl_secs` 3600, `token_clock_skew_secs` 300 (documented for verifiers), `default_user_tenant` `default`, `default_user_roles` `viewer`, `jwks_max_age_secs` 300. `docs/openapi.yaml`: tag `tokens`, paths `/token`, `/session/token`, `/.well-known/*`, `/admin/principals*`, `/admin/user-grants*`, `/admin/signing-keys`; securityScheme `principalSecret` (basic). Console (`ui/apps/console`): views **Principals** (create, secret-once panel, add secret, revoke with typed confirmation — clone `views/Keys.tsx`), **User grants**, **Signing keys** (read-only with the CLI commands printed). Add types/calls in `src/lib/api.ts`.

## 9. Threats and controls
- Signing key theft: 0600 file refused otherwise; never in DB/logs; `retire` kills outstanding tokens.
- Algorithm confusion: JWKS advertises only EdDSA; verifier spec pins `alg` before parsing claims; no HMAC path exists in the broker.
- Audience confusion: `aud` from the principal row / configured list only; verifier requires exact match.
- Tenant injection via IdP claims: not possible — tenant comes from `principal`/`user_grant` rows, never from request or IdP claims (v1 has no claim mapping).
- Secret brute force: 256-bit secrets, hashed; peer-keyed failure limiter (ADR-0016 `auth_failure_burst` 10/min).
- Issuance as DoS: sign cost ~50 µs; Tier B coalesced; public limiter when an IP header is configured; body cap 64 KiB.
- Clock skew: 300 s both sides; `iat` not in the future beyond skew.
- Stale JWKS after rotation: `next` published before `activate`; verifier refreshes on unknown `kid`; `retire` refused inside the max TTL window.
- Admin-lane escalation: principals cannot reach `/admin/*` or `/internal/token` (distinct tables, distinct lookups); admin key stays the only minting credential; an `admin`-kind principal is a log-less role, not a broker one.
- Token in logs: `token.issued` records `jti`, never the token; INV-12 grep test extended with a fixture token.

## 10. Build plan (5 slices)
CI a slice must pass (from `.github/workflows/ci.yml`): in `repo/` `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo check --workspace --all-targets` on 1.88, `cargo audit --deny warnings`; in `repo/ui/` `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm test`, `pnpm build`; at root `npx --yes @redocly/cli@latest lint docs/openapi.yaml`.

**S1 Signing keyring + JWT + publication** (worktree A, independent). Files: new `src/signing.rs` (keyring, `Issuer::sign(claims) -> String`, JWKS doc), `store/crypto.rs` (factor file helpers), `config.rs`, `main.rs` (subcommands), new `http/wellknown.rs` mounted in `http::router`, `telemetry/metrics.rs`. Tests: token signed here verifies with `jsonwebtoken` EdDSA against the served JWKS; kid derivation stable; JWKS lists `next`+`active`, not `retired`; ETag/304 and Cache-Control present; 501 when off; `retire` refused inside window; seed absent from `Debug`, JWKS, and log capture; boot creates the file only when enabled. Done when: a curl of `/.well-known/jwks.json` verifies a test token.

**S2 Principals + grants as data** (worktree B, independent of S1). Files: `store/mod.rs` (v5), `store/repo.rs`, `store/writer.rs` (variants), `http/admin.rs`, `audit.rs` (actions), console `api.ts` + two views. Tests: secret shown once, absent from list; two live secrets both resolve, revoking one leaves the other; revoking the principal refuses a still-live secret (predicate test); PUT updates indexes; slug validation; >64 indexes refused; Tier A row and mutation commit together (clone audit/tests.rs:95); **wiring test**: table of (route, expected audit action) covering every new `AdminWrite` variant, plus a `#[test]` that pattern-matches all variants of `AdminWrite` in a `match` so adding one without a route fails to compile-exhaustively in the table. Done when: console can create/revoke a principal against a running broker.

**S3 `/token` machine issuance** (sequential after S1+S2 merge). Files: new `http/token.rs`, `http/mod.rs`, `audit.rs` (coalescing generalised), `main.rs`. Tests: happy path claims exactly `{iss,sub,aud,exp,iat,jti,tenant,kind,scopes,indexes}`; Basic auth path; form field `tenant=evil` ignored; `ttl` above max → `invalid_request`; revoked principal → `unauthorized_client`; wrong secret → `invalid_client` and 429 after burst; `last_used_at` advanced; `token.issued` row carries `jti` not the token; second issuance within window coalesces, refusal never does; 501 when off.

**S4 `/session/token` user issuance** (parallel with S3 after S2; same branch as S3 only if `http/mod.rs` conflicts worry you). Files: `http/session.rs` or new `http/user_token.rs`, `config.rs`. Tests: CSRF refused before any lookup; no cookie → `invalid_session`; stale generation → refused; grant found → claims incl. `sid`; no grant + default tenant → default claims; no grant + no default → 403 `no_grant`; two grants without `tenant` → 400; unknown aud → 400; `exp ≤ absolute_exp`; audit row.

**S5 Contract, docs, console polish** (parallel with S3/S4 for docs; console after S2/S4 shapes settle). Files: `docs/openapi.yaml`, new `docs/decisions/ADR-0017-token-issuer.md`, `docs/architecture/observability.md` §4/§6, `.context/invariants.md` (INV-12 list), `.context/current-state.md`, `repo/.cargo/audit.toml` comment, console Signing-keys view. Done when: redocly lint and `pnpm build` green and ADR accepted.

## 11. Reference verifier (what log-less implements)
Checks, in order, fail-closed: (1) header parses; `typ` absent or `JWT`; `alg == "EdDSA"` exactly (reject anything else before looking at keys); `kid` present. (2) Find `kid` in cache; if missing and last refresh > 60 s ago, refresh JWKS once; still missing → reject `unknown_kid`. (3) Verify Ed25519 signature over `b64(header).b64(payload)`. (4) `iss` equals configured issuer string exactly. (5) `aud` equals configured audience (string or array containing it). (6) `exp > now − 300`; `iat < now + 300`. (7) `tenant` present, non-empty, slug-shaped; `kind` in the known set; `scopes`/`indexes` arrays of strings. (8) Authorise: tenant from the token names the path prefix; index allow-list check (`"*"` matches all); scope check per operation. Never read tenant/index from the request.
JWKS cache: fetch at startup and hourly from `jwks_uri` (discovery optional); honour `ETag`; on any fetch failure keep the cache and keep verifying for up to 30 days from the last successful fetch, then warn but **still verify** (an edge that goes dark must not stop ingesting; static config keys remain the bootstrap path). Persist the cache to disk so a restart while disconnected works. `ring` 0.17 is already in log-less's lock (Cargo.lock:1307) and verifies Ed25519 without a new crate.
Test vectors (described): **V1** valid ingest token: kid of the active key, `tenant:"acme"`, `kind:"ingest"`, `indexes:["default"]`, `exp` +24 h — must accept writes to `tenant=acme/index=default`, refuse `index=payments` and any other tenant. **V2** same payload re-signed with a key not in the JWKS (or `alg` rewritten to `HS256` with the public key as HMAC secret) — must reject at step 1/2, never reach claims. **V3** valid signature, `aud:"other"` or `exp` 10 minutes past with skew 300 s — must reject at step 5/6; the same token at `exp` 2 minutes past must accept.

## 12. Decisions only the owner can make
1. Public vs internal listener for `/token` and JWKS (recommended public; needs the public lane reachable by machines).
2. `machine_token_max_ttl_secs` ceiling (30 d default vs 365 d "paste forever").
3. Audience string(s) for log-less (`logless`) and whether existing platform services ever adopt JWTs.
4. Self-host defaults: `default_user_tenant=default`, `default_user_roles=viewer` — or require explicit grants.
5. Whether the broker retains IdP claims for future group mapping (v2) or membership stays broker-side data.

## 13. Deliberately not built
Token exchange/down-scoping; introspection route; revocation list; per-component audiences; IdP group→tenant mapping; tenant table/quotas; forced rotation or mandatory secret overlap; mTLS/DPoP; refresh tokens for machines; admin HTTP key rotation; console tests (console has none today; CI gates only typecheck/build).

### Critical Files for Implementation
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/store/crypto.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/store/writer.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/http/admin.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/http/internal.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/config.rs
