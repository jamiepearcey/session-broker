# Token issuer: what is being built (pragmatic scope)

Status: accepted for build, 2026-10-11. This file wins over `token-issuer.md` wherever they differ.
`token-issuer.md` is the consultant's full design; it was written before the owner's steer below.

## Owner steer

Be pragmatic. Match what the market ships (Sentry, Datadog, Splunk, Grafana, Elastic): long-lived API
keys an operator creates once and pastes into config, OIDC sign-on for people, standard JWTs. Do not
exceed that by default. Auth must not become a pain and must not take ingest down.

## Principles

1. The simple path is: create a principal, get a secret, paste it. Secrets are long-lived and do not
   expire unless an operator says so.
2. Rotation and revocation are operations an operator can run. Nothing forces them.
3. Signed short-lived tokens exist for the cases that need them: a console acting for a signed-in
   user, and hosted multi-tenant deployments. A consumer that only wants static keys in its own
   config never needs the broker.
4. The feature is off until `token_issuer` and `issuer_audiences` are set. Existing routes and bodies
   do not change.
5. Sensible defaults, few knobs.

## Built (slices, in order, one branch)

- **S1 Signing core and schema v5.** As `token-issuer.md` sections 1, 2 and 4: Ed25519 JWTs, seed
  sealed in the store under the custody keyring, a key created at first boot, all five tables in one
  migration, `rotate-signing-key` as an admin route and CLI.
- **S2 Tenants, principals, user grants on the admin lane.** As section 4, with these changes: a
  principal secret has no expiry by default; "rotate" adds a new secret and leaves the old one valid
  until the operator revokes it (an optional `expire_old_in_secs` may be passed); no forced overlap.
- **S3 Publication and config.** JWKS and the issuer metadata document as section 3. Change: an
  `http://` issuer off loopback logs a warning at start; it is not refused (TLS is optional by owner
  decision). No `issuer_allow_plaintext` setting.
- **S4 Machine tokens, `POST /auth/token`** (client credentials), as section 5a. Change: keep the
  per-client failure limiter only; no per-principal success limiter.
- **S5 User tokens, `POST /session/token`**, plus the opt-in `token_type: "broker"` on
  `/internal/token`, as section 5b. Tenant and roles come from the broker's `user_grant` table.
- **S6 Console views**: principals (with tenants as a filter and a create form), user grants,
  signing keys.
- **S7 ADR-0017, openapi, invariants, verifier spec and test vectors.**

## Defaults (changed from the consultant's where marked)

| Setting | Value | Note |
|---|---|---|
| Machine token lifetime | 3600 s, per-principal maximum up to 86400 s | as designed |
| User token lifetime | 3600 s, capped at the session's idle expiry | changed from 600 s |
| Verifier clock allowance | 300 s either way | changed from 60 s |
| Signing key publish lead | 86400 s | as designed; rotation is optional |
| Verifier key cache | refresh hourly; keep serving the cache while the broker is unreachable, with no time limit | as designed |
| Principal secret expiry | none | changed |

## Deliberately not built

Recorded so these are choices, not gaps. None of the vendors above ships them by default.

- Token introspection (`/internal/introspect`) and any per-request online check.
- Token exchange and down-scoping.
- A signed-token header on `/authz`.
- A `jti` replay cache.
- A per-principal issuance rate limit.
- Mandatory secret expiry, forced rotation schedules, or a required two-secret overlap.
- Refusing plaintext issuers (a warning instead).
- Mapping tenant or roles from identity-provider group claims (the grant table is the source).
- Per-tenant admin delegation in the console.
- Mutual TLS as a requirement anywhere.

## Honest limits

- An issued token cannot be revoked before it expires. Revoking a principal, a secret or a grant
  stops new tokens at once; outstanding ones live out their lifetime (an hour by default).
- Losing the custody keyfile loses the signing keys as well as the upstream tokens.

## Addendum: adopted from the consultant's second pass (binding for S2 onward)

The consultant revised the design after the owner's steer (`token-issuer-v2-pragmatic.md`). S1 keeps
the first design (signing seed sealed in the store, created at first boot). From S2 onward these
simpler choices apply, and they win over `token-issuer.md` and over anything above that conflicts:

- **No tenant step.** The `tenant` table from S1 stays, but nobody has to create a tenant: creating
  a principal or a user grant with a tenant slug inserts the tenant row if it is missing, in the
  same transaction. Slug rule `^[a-z0-9][a-z0-9-]{0,62}$`. `default` is pre-seeded.
- **One audience per consumer product**, not per component: for log-less it is `logless` for the
  agent, central and console alike. Deployments are told apart by `iss`.
- **Secret prefix `sbp_`** on principal secrets (so secret scanners can spot them); ids `sp_`.
- **Machine tokens:** default lifetime 86400 s (was 3600); per-principal maximum default 30 days,
  allowed up to 365 days. `POST /auth/token` also accepts HTTP Basic for the client id and secret,
  and an optional `ttl` no larger than the principal's maximum.
- **Claim names:** `scopes` and `indexes` as JSON arrays of strings (`["*"]` means every index of
  the tenant), `roles` an array on user tokens, header `typ: "JWT"`. If S1 fixed other names,
  rename them in S4; no consumer exists yet.
- **User tokens on a single-tenant install need no grant.** If the signed-in user has no grant and
  `default_user_tenant` is set (default `default`), issue for that tenant with `default_user_roles`
  (default `viewer`) and `indexes: ["*"]`. Setting `default_user_tenant` to empty requires explicit
  grants.
- **`/internal/token` is NOT changed.** Drop the `token_type: "broker"` extension from S5; the
  console calls `POST /session/token`.
- **Key publication:** `Cache-Control: public, max-age=300, stale-if-error=2592000` and an `ETag`
  with 304 on `If-None-Match`.
- **Rate limiting on `/auth/token`:** failures only, using the existing limiter.

Defaults table above is superseded where this addendum differs (machine token lifetime).

**Precedence note for implementers.** Your task prompt was written before this addendum. Where the
prompt and this addendum disagree (machine token lifetime, claim names, the `/internal/token`
extension, tenant creation, audience naming), follow this addendum and say so in your report.
