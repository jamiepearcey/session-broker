<!-- Status: PROPOSED 2026-10-11. Consultant design (first pass, written before the owner's 'be pragmatic' steer). See token-issuer-scope.md for what is actually being built. -->

# session-broker as token issuer: implementation design

Repo paths below are under `/Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/` unless absolute. Verified facts are cited; unverified items are marked **[unverified]**.

**Scope note (must be an ADR-0017).** ADR-0001 says "not multi-tenant, no RBAC". This change keeps the broker out of policy *evaluation* (it stamps attested attributes; resource servers enforce) but makes it a token issuer that holds tenant/principal/grant data. Write ADR-0017 amending ADR-0001 and ADR-0006 ("no JWKS surface needed" at `docs/decisions/ADR-0006` lines 566-568 becomes false for *issued* tokens; session cookies stay opaque).

## 1. Token format

**JWT, compact JWS, `alg=EdDSA` (Ed25519).** Rejected ES256: p256 is in the lock too, but ECDSA needs nonce discipline and DER/raw-sig ambiguity across libraries; Ed25519 is deterministic, one JWK field (`x`), fastest verify. Rejected PASETO: no crate in `Cargo.lock`, no ecosystem in log-less, and the interop test below needs an independent implementation.

Header: `{"alg":"EdDSA","typ":"at+jwt","kid":"<kid>"}`. Claims:

| claim | machine | user |
|---|---|---|
| `iss` | config `token_issuer` | same |
| `sub` | `principal_id` (`sp_…`) | IdP `sub` (as `/internal/token` returns) |
| `aud` | single string, the principal's bound audience | single string, requested, must be in `issuer_audiences` |
| `exp`,`iat`,`jti` | `jti` = 16 CSPRNG bytes base64url (`token::fill_random`) | same |
| `tenant` | principal's tenant | the `user_grant` tenant |
| `kind` | `ingest|node|replica|reader|admin` | `"user"` |
| `name` | principal name (log-less uses it as `node=` id) | absent |
| `scope` | space-delimited string (RFC 8693/9068 spelling) | from grant roles->scopes? No: `roles` array; `scope` absent |
| `idx` | JSON array of index names, or `["*"]` | from grant |
| `roles` | absent | JSON array |
| `sid` | absent | broker `Sid` (never the cookie) |

`nbf` omitted (a token minted now has no future start; one less skew failure). Size budget: ≤1 KiB typical, hard cap 4 KiB enforced at principal/grant creation (`idx` ≤64 names, `scope` ≤512 bytes, `roles` ≤32). Clock rule: broker uses `Clock::now()` for `iat`/`exp`; verifiers allow ±60 s on `exp` and `iat`.

**Crates.** `ed25519-dalek` 2.2.0 is already in the broker's graph via `openidconnect` 4.0.1 (`Cargo.lock` lines 631-642, 1491-1519) with `signature`/`zeroize` but **no `rand_core`/`pkcs8` features** (not in its dep list). Add it as a direct dep (`ed25519-dalek = "2.2"`, workspace table) — zero new transitive crates. Generate seeds with `token::fill_random` and `SigningKey::from_bytes`. Write a ~60-line compact-JWS encoder (`issuer/jwt.rs`: `base64url(header).base64url(payload)` signed, `base64` 0.23 `URL_SAFE_NO_PAD` as in `store/crypto.rs:42`). Add `jsonwebtoken` (workspace dep, `rust_crypto`) as a **dev-dependency only** so the interop test verifies our tokens with an independent decoder (`DecodingKey::from_jwk` / `from_ed_components` **[unverified: API names in jsonwebtoken 11; registry sources not extracted, `cargo tree --offline` fails]**). No RSA: amend the `RUSTSEC-2023-0071` reason in `repo/.cargo/audit.toml` (its "revisit when the broker gains a private key" clause is now triggered; the Marvin rationale still holds because the key is Ed25519, not RSA). `cargo tree -i ed25519-dalek -e features` must be run online in slice 1 to confirm no feature set change **[unverified]**.

## 2. Signing keyring

**Keys live in the store (schema v5 table `signing_key`), the 32-byte seed sealed under the ADR-0016 custody keyring** with AAD context `signing:<kid>:seed` (`store::crypto::seal`, `context()` at `crypto.rs:364`). Rejected separate keyfile: a second file to back up/permission-check, left behind by the ADR-0005 Postgres path, and no transactional audit. Rejected putting seeds in the custody keyring file: it conflates a symmetric at-rest key that must never leave the box with a key that has a public half and a publish/retire lifecycle. Backup unit stays "db + keyfile" (ADR-0016). Losing the keyfile loses signing keys with the upstream tokens — same recovery story, document it.

State derived from timestamps, no state column (the recurring defect is a state nobody transitions): `activate_at`, `retire_at` (NULL = open), `removed_at`. Active key = newest row with `activate_at <= now AND removed_at IS NULL`; pending = `activate_at > now`; published = `removed_at IS NULL AND (retire_at IS NULL OR retire_at > now)`. `kid` = base64url(SHA-256(public)[..8]) — derived from material, collision-free, unforgeable-ish.

Rotation (`POST /admin/signing-keys/rotate {"activate_in_secs": N}`; CLI `session-broker rotate-signing-key [--now]` for the stopped-broker case, reusing the `run_subcommand` shape at `main.rs:427`): inserts a key with `activate_at = now + N` (default `signing_key_publish_lead_secs` = 86400) and sets the current active key's `retire_at = activate_at + issuer_max_ttl_secs + 300`. `N = 0` is emergency rotation: new key signs immediately and old key gets `retire_at = now` — offline verifiers reject new tokens until their next JWKS refresh; say so in the response body. Tier A audit (`signing_key.rotated`) rides the same `AdminWrite` (pattern: `http/admin.rs:235-275`). Hourly prune sets `removed_at` on keys past `retire_at` (ride the existing `run_audit_pruner`/`PruneAudit` command rather than a new task — `main.rs:525`).

Boot with no key: `issuer::bootstrap(reader, writer, audit, clock)` reads keys; if none, generates one and writes through with a Tier A `signing_key.created` row (actor `system`). Boot `Reseal` (`writer.rs:558`, `repo::reseal_custody`) must be extended to `signing_key.seed_sealed` — add a test that a seed sealed under key 1 is resealed under key 2 after `rotated_for_test()` (`crypto.rs:355`), or the predicate will silently never touch the new table. Issuer holds an in-memory `RwLock<KeyCache>`; the admin rotate handler calls `issuer.reload()` after its ack; issuance also lazily reloads when `now > next_reload` (60 s) so a second node (future HA) converges without a background task.

INV-5 applies to the seed (sealed, zeroized `SigningKey`, never in any response); INV-12 gains `kid` and `jti` as permitted identifiers and forbids seeds, principal secrets and issued tokens; INV-13 widens "credential" to principal secrets, user grants and signing keys.

## 3. Publication, TTLs, revocation

Public listener (agents are outside the operator network; the key is public): `GET /auth/jwks.json` (inside the already path-mounted `/auth/*` prefix, ADR-0012 — no new edge rule) and `GET /.well-known/oauth-authorization-server` (RFC 8414; one new edge rule, optional — agents configure `jwks_uri` directly). JWKS body: `{"keys":[{"kty":"OKP","crv":"Ed25519","kid","x","use":"sig","alg":"EdDSA"}]}` for every *published* key. Handlers set `Cache-Control: public, max-age=300, stale-while-revalidate=86400` and a `Date` header explicitly; `hardening::security_headers` only sets `no-store` when absent (`http/hardening.rs:95`), so a test must assert JWKS is not `no-store`. Both answer `501 lane_disabled` when the issuer is unconfigured.

TTLs: machine default 3600 s (`issuer_machine_ttl_secs`), per-principal `max_ttl_secs` ≤ `issuer_max_ttl_secs` (86400); user default 600 s, capped at the session's `idle_exp` and 3600 s. Trust window: verifier refreshes hourly, serves from cache indefinitely while refresh fails (metric `jwks_stale_seconds`), refreshes immediately on unknown `kid` (≥60 s apart). With publish lead L=24 h, an agent whose last successful refresh was R verifies every token minted at T unless it was disconnected for longer than L *and* a rotation activated in that gap.

Revocation, honestly: there is none for an outstanding token; the controls are short TTL plus principal/secret/grant revocation stopping *new* issuance within one request. Instant revocation requires an online check: an optional `POST /internal/introspect` (internal listener, backend-key guarded, RFC 7662 shape, answers `active:false` if the principal/grant/key is revoked) for online components (log-less central before minting S3 credentials), never for agents. Compromise of a key: emergency rotation invalidates everything within one JWKS refresh.

## 4. Service principals as data (schema v5, one migration in slice 1)

New tables, not `api_key`: an `api_key` row can act as *any user* on `/internal/token` (`repo.rs:323 find_live_api_key`); a principal must never be resolvable there. Secrets carry class prefixes (`sp_` vs the existing `bk_` ids) so the wrong lane rejects before hashing.

```sql
CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, display_name TEXT, created_at INTEGER NOT NULL, disabled_at INTEGER);
INSERT INTO tenant VALUES ('default', 'default', strftime('%s','now'), NULL);  -- self-host needs no config
CREATE TABLE principal (
  principal_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenant(tenant_id),
  name TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('ingest','node','replica','reader','admin')),
  scope TEXT NOT NULL, indexes TEXT NOT NULL,           -- JSON array or '*'
  audience TEXT NOT NULL, max_ttl_secs INTEGER NOT NULL,
  created_at INTEGER NOT NULL, created_by TEXT, last_used_at INTEGER, revoked_at INTEGER,
  UNIQUE (tenant_id, name));
CREATE TABLE principal_secret (
  secret_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principal(principal_id),
  secret_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER);
CREATE INDEX principal_secret_live ON principal_secret(secret_hash) WHERE revoked_at IS NULL;
CREATE TABLE user_grant (sub TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenant(tenant_id),
  roles TEXT NOT NULL, indexes TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT, revoked_at INTEGER,
  PRIMARY KEY (sub, tenant_id));
CREATE TABLE signing_key (kid TEXT PRIMARY KEY, public_key BLOB NOT NULL, seed_sealed BLOB NOT NULL,
  created_at INTEGER NOT NULL, activate_at INTEGER NOT NULL, retire_at INTEGER, removed_at INTEGER);
```

Secrets: 32 CSPRNG bytes, shown once, SHA-256 at rest (same as `api_key`; a 256-bit random value needs no slow hash). Rotation inserts a new secret and sets the old one's `expires_at = now + grace` (default 86400). Lookup predicate: `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?now)` with `now` bound from `Clock` — **predicate hazard**: a test must drive the clock past `expires_at` and see refusal, and inside it and see acceptance. Tenants are data (a typo in a free-form string silently creates a tenant); `default` is pre-seeded so self-host is zero-config. Audiences are config (`issuer_audiences`, comma list), not data: an audience is a deploy-time fact.

Admin routes (internal listener, existing `authorised()` admin-key guard at `http/admin.rs:108`; backend keys must fail, extend `every_route_refuses_without_the_admin_key`): `GET/POST /admin/tenants`, `DELETE /admin/tenants/{id}` (disable); `GET/POST /admin/principals`, `GET /admin/principals/{id}`, `DELETE /admin/principals/{id}` (revoke); `POST /admin/principals/{id}/secrets` (rotate, returns the new secret once), `DELETE /admin/principals/{id}/secrets/{secret_id}`; `GET/POST /admin/user-grants`, `DELETE /admin/user-grants/{sub}/{tenant}`; `GET /admin/signing-keys`, `POST /admin/signing-keys/rotate`. All mutations are Tier A via new `AdminWrite` variants.

## 5. Issuance endpoints

**(a) Machine: `POST /auth/token`, public listener**, `application/x-www-form-urlencoded` only (RFC 6749 §4.4: `grant_type=client_credentials&client_id=<principal_id>&client_secret=…[&scope=…]`); rejected JSON: one body shape to validate and limit, and every OAuth client/curl speaks forms. Response RFC 6749 §5.1 `{access_token, token_type:"Bearer", expires_in, scope}`; errors `{error, error_description}` with `error` ∈ `invalid_request`(400), `invalid_client`(401 + `WWW-Authenticate`; unknown/revoked/expired secret, revoked principal, disabled tenant — one code, no oracle), `invalid_scope`(400, requested scope ⊄ principal scope), `lane_disabled`(501). `client_id` prefix check (`sp_`) before any store read. Tenant is never a request parameter. No store write per issuance except `last_used_at` coalesced through a new `AdminWrite::TouchPrincipal`, reusing the `TOUCH_INTERVAL` pattern at `http/internal.rs:72-134` — **wiring hazard**: a test must observe `last_used_at` populated after a flush. Rate limits: failures per `client_id` bucket (`issuer_client:<id>`, existing `Limiter`, independent of client IP so it works without `rate_limit_client_ip_header`), plus the public IP limiter when configured; successes per principal (`issuer_issue:<id>`, 60/min) so a compromised agent cannot spin. TLS is optional in the deployment, so the secret can travel in clear: refuse to enable the issuer when `base_url` is `http://` off loopback, same rule as `HttpConfig::new` (`http/mod.rs:83`), overridable by `issuer_allow_plaintext=true`.

**(b) User: `POST /session/token`, public lane**, cookie-authenticated, INV-2 `require_same_origin` (`http/guards.rs:27`), JSON `{"audience": "...", "tenant": "<optional if the user has one grant>"}` → `{access_token, token_type, expires_in, tenant, roles, indexes}`. Requires `Resolution::Active` exactly like `/authz` (`http/authz.rs:118`). New `ErrorCode::NotGranted` (403) and `BadAudience` (400). Lanes are kept: `/internal/token` still returns the upstream token (INV-11, unchanged) but gains an optional body field `"token_type": "upstream" | "broker"` (+`audience`) so an existing backend holding a cookie can obtain a broker-signed user token with the same dual auth — opt-in, default `upstream`, so nothing breaks. `/authz` is untouched. `AppState` (`http/mod.rs:211`) gains `issuer: Option<Arc<Issuer>>`; `Issuer` owns `Reader`, `WriterHandle`, key cache, config, so `AppState` does not acquire a store handle.

Tenant/roles source: **broker-side `user_grant` table** (sub → tenant, roles, indexes), administered on the admin lane with Tier A audit. Rejected IdP group mapping: claim names vary per IdP, membership would be defined where INV-13 cannot record it, and `oauth.rs:403-407` currently keeps only `sub` from the verified claims — exposing more needs `openidconnect`'s `AdditionalClaims` generic **[unverified]**. Leave `oidc_group_claim` + mapping as an owner decision for later.

**(c) Exchange/down-scoping**: optional slice, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on `/auth/token`, subject token verified against the broker's own published keys, requested `audience`/`scope`/`idx` must be ⊆ the original, `exp` ≤ original, fresh `jti`. Only build if log-less central needs a narrower token for the S3 exchange.

## 6. Audience model

One `aud` string per consumer deployment, exact match, registered in `issuer_audiences`. Naming convention: `logless:<deployment-id>:agent`, `logless:<deployment-id>:central`, platform services `svc:<name>`. Each principal is bound to exactly one audience at creation; user tokens must name one. A verifier checks equality with its own configured audience and nothing else, so a token for central is useless at an agent and vice versa.

## 7. Audit and metrics

Tier A (same transaction): `tenant.created`, `tenant.disabled`, `principal.created`, `principal.revoked`, `principal.secret_rotated`, `principal.secret_revoked`, `user_grant.created`, `user_grant.revoked`, `signing_key.created`, `signing_key.rotated`. Tier B: `token.issued` (actor `backend` with `actor_id=principal_id`, or `user` with `subject=sub`; `detail {aud, kind, tenant, kid, jti, ttl}`; coalesced per `(actor_id, aud)` per `audit_coalesce_secs` — generalise `should_record_exchange` at `audit.rs:376`), `token.issuance_refused` (never coalesced, `reason` = the error code), `signing_key.removed` (system, at prune). JWKS reads: metrics only. INV-12: never a token, secret, or seed; `jti` and `kid` are fine. Extend `telemetry::tests::no_secret_material_reaches_any_sink` and `audit/tests.rs:337` with fixtures: a principal secret, a signed token, a seed. Metrics (`telemetry/metrics.rs`): `broker_tokens_issued_total{kind,outcome}`, `broker_signing_keys{state="pending|active|retired"}` (sampled at scrape in `http/ops.rs:metrics`), `broker_signing_key_active_age_seconds`.

## 8. Compatibility and config

Feature is off until `token_issuer` (must equal `base_url` or a URL under it) and `issuer_audiences` are set; `config.rs` validates the pair the way it validates `oidc_issuer_url`+secret (`config.rs:196`). Unconfigured routes answer `501 lane_disabled`; existing routes and bodies are unchanged. New config (all `BROKER_*`): `token_issuer`, `issuer_audiences`, `issuer_machine_ttl_secs=3600`, `issuer_user_ttl_secs=600`, `issuer_max_ttl_secs=86400`, `signing_key_publish_lead_secs=86400`, `issuer_jwks_max_age_secs=300`, `issuer_secret_rotation_grace_secs=86400`, `issuer_allow_plaintext=false`, `issuer_introspection_enabled=false`. `docs/openapi.yaml`: new tag `issuer`; paths `/auth/token`, `/auth/jwks.json`, `/.well-known/oauth-authorization-server`, `/session/token`, `/internal/token` (extended body), `/internal/introspect`, the `/admin/{tenants,principals,user-grants,signing-keys}` family; securityScheme `principalSecret`; schema `OAuthError`. Console (`ui/apps/console/src`): `lib/api.ts` types + calls; views `Principals.tsx` (tenant filter, create form with kind/scope/indexes/audience/max TTL, one-shot secret panel and typed-revoke lifted from `views/Keys.tsx`, rotate secret), `UserGrants.tsx`, `SigningKeys.tsx` (kid, derived state, activate/retire times, rotate with lead field, red emergency variant); register in `App.tsx` `VIEWS`.

## 9. Threats and controls

- **Key theft**: seed sealed under custody keyring, `0600` keyfile, emergency rotation (admin route + CLI), Tier A record of every rotation, verifier caches refresh ≤1 h.
- **Algorithm confusion**: broker emits only `EdDSA`; JWKS contains only OKP keys; verifier rejects any other `alg`/`none` before key lookup. Test: re-sign a valid payload as HS256 using the public key as secret; the reference verifier (jsonwebtoken, algorithms fixed to EdDSA) must reject.
- **Audience confusion**: single string `aud`, principal bound to one audience, exact match at verifier.
- **Tenant injection**: tenant comes only from `principal.tenant_id` or `user_grant`; `/auth/token` has no tenant parameter; `/session/token` with a tenant lacking a grant → 403. Never from IdP claims.
- **Secret brute force**: 256-bit secrets, per-client-id failure limiter independent of IP, refusals audited uncoalesced, 429 with `Retry-After`.
- **Issuance DoS**: Ed25519 sign is tens of µs, no store write per issuance, 64 KiB body cap, per-principal success limiter.
- **Clock skew**: `Date` header on JWKS/metadata so agents can measure and warn; ±60 s verifier skew; tokens never backdated.
- **Stale JWKS after rotation**: publish lead ≥ refresh interval + disconnect tolerance; retired keys published ≥ max TTL; verifier refreshes on unknown kid.
- **Admin-lane escalation**: principal secrets cannot authenticate on `/internal/token` or `/admin/*` (separate table, prefix check, explicit negative tests); `kind=admin` is a log-less role, never broker admin; `max_ttl` capped globally; scope/role grammar `[a-z0-9:._-]{1,64}`.
- **XSS residual**: `/session/token` is CSRF-guarded but drivable by script on the app origin (same residual ADR-0007 states); mitigated by 10-min TTL and audience binding. State it.

## 10. Build plan

CI gates every slice must pass (from `/Users/jamiepearcey/projects/security/session-broker/.github/workflows/ci.yml`): in `repo/`: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo check --workspace --all-targets` on toolchain 1.88, `cargo audit --deny warnings`; in `repo/ui`: `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm test`, `pnpm build`; at the outer root: `npx --yes @redocly/cli@latest lint docs/openapi.yaml`.

**Wiring rule for every slice** (the recurring defect): each new `AdminWrite`/`Command` variant gets exactly one `pub` sender on `WriterHandle` or a handler, and a test that goes through the *handler or bootstrap fn* (never the variant directly) and observes the row via a second connection, as in `writer.rs:625 custody_write_durability_ack_fires_only_after_commit`. Every new SQL predicate with a time or state term gets a clock-driven pair test (matches / does not match).

**S1 — signing core + schema v5** (sequential, first, on one branch). Files: `store/mod.rs` (SCHEMA_VERSION 5, all tables above), `store/repo.rs` (signing_key CRUD, reseal extension), `store/writer.rs` (`AdminWrite::InsertSigningKey`, `RotateSigningKey`, `RemoveRetiredSigningKeys`), new `issuer/{mod,jwt,keys}.rs`, `audit.rs` actions, `main.rs` (`issuer::bootstrap`, CLI `rotate-signing-key`), `.cargo/audit.toml` note, `Cargo.toml` deps. Tests: sign→verify via jsonwebtoken dev-dep; JWKS document shape; kid derivation; seed absent from the DB file (grep, like INV-5); bootstrap creates exactly one key and one Tier A row; rotate with lead leaves old key active and new pending; emergency rotate; retired key published until `retire_at`, removed after; reseal moves `seed_sealed` onto a rotated custody key; HS256-with-public-key rejected. Done when: a token signed by a fresh store verifies with an independent decoder and the DB file contains no seed bytes.

**S2 — tenants, principals, grants: data + admin lane** (worktree A, after S1). `store/repo.rs`, `store/writer.rs` (`AdminWrite` variants), `http/admin.rs`, `ui/apps/console/src/lib/api.ts` types. Tests: create/list/revoke; secret shown once; rotate yields two live secrets then one after grace (clock-driven predicate test); revoked principal's secret refused; backend key refused on every new route; Tier A row and mutation commit together; a principal secret presented to `/internal/token` and `/admin/*` is refused. Done when the console types compile against the responses.

**S3 — publication + config** (worktree B, after S1, parallel with S2). `config.rs` (all issuer fields, validation, plaintext rule), `http/mod.rs` (routes), new `http/issuer_public.rs` (JWKS, metadata), `main.rs`. Tests: 501 when unconfigured; cache headers present and not `no-store`; `Date` header; metadata `jwks_uri`/`issuer` match config; config validation negatives. Done when an agent can fetch keys and verify an S1 token.

**S4 — machine issuance `/auth/token`** (worktree C, after S2+S3 merge; parallel with S5). `http/issuer_public.rs`, `issuer/mod.rs`, `store/writer.rs` (`TouchPrincipal`), `telemetry/metrics.rs`, `audit.rs`. Tests: happy path (claims exact, `aud`, `tenant` from row, `exp-iat == ttl`); wrong secret → 401 `invalid_client`; revoked/disabled → 401; scope superset → `invalid_scope`; JSON body → 400; `last_used_at` populated after flush (**wiring test**); failure limiter trips per client_id without an IP header; `token.issued` coalesces, refusals do not; no secret/token in captured logs.

**S5 — user issuance** (worktree D, parallel with S4). `http/session.rs` or new `http/user_token.rs`, `http/error.rs`, `http/internal.rs` (`token_type`), `http/mod.rs`. Tests: CSRF-rejected without `Sec-Fetch-Site`; stale generation refused; no grant → 403; two grants without `tenant` → 400; `exp` capped by `idle_exp`; `/internal/token` default body unchanged (existing tests pass untouched); `token_type:"broker"` with both halves yields a user token, either half alone yields nothing.

**S6 — console views** (worktree E, after S2; parallel with S4/S5). `Principals.tsx`, `UserGrants.tsx`, `SigningKeys.tsx`, `App.tsx`. Gate: `pnpm typecheck && pnpm build` (console has no vitest suite today; `pnpm test` covers react-sdk only).

**S7 — docs, contract, invariants, vectors** (sequential, last). ADR-0017, `docs/openapi.yaml`, `docs/architecture/observability.md` §4-6, `.context/invariants.md` (INV-12/13 wording), `.context/current-state.md`, `README`, plus `docs/verifier/vectors.json` generated by a test with a fixed seed (test-only key). Gate: redocly lint.

**S8 — optional** (after S4/S5): `/internal/introspect`, token exchange, and an opt-in `x-broker-token` header on `/authz` (per-request sign on the hot path: CPU only, no store write, metrics only — owner decision).

Merge hotspots: `store/writer.rs` `AdminWrite` enum and `main.rs` are touched by S1/S2/S4/S5 — trivial but real conflicts; land S1 before branching.

## 11. Reference verifier spec (for log-less)

Checks, in order, each a distinct rejection reason: (1) split into exactly 3 base64url-no-pad parts; parse header; reject unless `alg == "EdDSA"`, `typ == "at+jwt"`, `kid` present, no `crit`. (2) Resolve `kid` in the cache (static config keys count, under a `static:` prefix); unknown → one rate-limited refresh (≥60 s apart) → still unknown → reject `unknown_kid`. (3) Verify the Ed25519 signature over the ASCII bytes `header.payload` (log-less already has `ring` in its lock, which verifies Ed25519; or `ed25519-dalek`). (4) Parse claims; require `iss, sub, aud, exp, iat, jti, tenant, kind`; `iss` exact string equality with configured issuer; `aud` must be a string equal to the verifier's own audience; `exp > now - 60`; `iat <= now + 60`; if `nbf` present, `nbf <= now + 60`; reject `exp - iat > 90000` (bounds a misconfigured issuer). (5) Enforce: tenant from the claim and nowhere else; `kind` in the endpoint's allowed set; `scope` contains the required scope; `idx` is `["*"]` or contains the requested index; for `kind=node`, `name` equals the node id in the path. (6) Optional `jti` replay cache for admin-kind mutations.

JWKS cache policy: fetch at start if reachable; persist to `<data>/jwks-cache.json` with `fetched_at`; refresh hourly with jitter, honouring `max-age` as a floor; on failure keep serving the cache indefinitely and expose `jwks_stale_seconds`; never evict keys on a failed refresh; replace atomically on success; log a warning if `|Date - local| > 30 s`.

Test vectors (fixed test seed, generated by S7): **V1** valid ingest token (`tenant=acme`, `idx=["default"]`, `scope="ingest"`, `aud=logless:test:agent`, `exp=iat+3600`) verified at `iat+10` → accept. **V2** V1's payload with `aud=logless:test:central`, correctly signed → reject `audience`; and V1 re-signed as `alg=HS256` using the public key bytes as the HMAC secret → reject `alg`. **V3** user token (`kind=user`, `sid`, `roles=["viewer"]`, `exp=iat+600`) verified at `iat+30` → accept; at `iat+700` → reject `expired`; with `kid` altered to an unknown value → reject `unknown_kid`.

## 12. Owner decisions

1. Accept ADR-0017's scope change (tenants/principals/grants as broker data; still no policy evaluation).
2. Publish lead and emergency-rotation posture (24 h default; is a cache-refresh-sized outage on emergency rotation acceptable?).
3. User tenant/roles from the broker grant table (recommended) vs. IdP group mapping later.
4. `/auth/token` on the public listener with the plaintext-off-loopback refusal; any deployment needing http issuance must set `issuer_allow_plaintext`.
5. Whether to build S8 (introspection, token exchange, `/authz` token header).
6. Scope/role vocabulary for log-less kinds — the broker validates grammar only.
7. Per-tenant admin delegation (console RBAC) is out of scope; confirm.

**Unverified**: jsonwebtoken 11 OKP/JWK API names; ed25519-dalek enabled feature set (cargo offline failed); openidconnect additional-claims generic; log-less verification stack specifics beyond `ring` being in its `Cargo.lock`.

### Critical Files for Implementation
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/store/writer.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/store/crypto.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/http/admin.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/http/internal.rs
- /Users/jamiepearcey/projects/security/session-broker/repo/crates/session-broker/src/config.rs
