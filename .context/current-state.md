# Current State

_Last updated: 2026-10-11_

## Status

_Updated 2026-07-26._ **The broker boots and has been driven end to end against
a running mock IdP.** M0–M5a are implemented and green (112 crate tests + 10 in
`mock-idp`, clippy clean under `-D warnings`). M7 (React SDK) and M8 (demo app)
are implemented and unit-tested in isolation (`repo/ui/`, 50 vitest tests) but
have **not** been pointed at the running broker yet — no browser verification.

### Verified by running it, not by reading it

With `mock-idp` on `127.0.0.1:9090` and the broker on `:8080` / `:8091`:

| Claim | Result |
|---|---|
| `/auth/login` → IdP → `/auth/callback` → session cookie | ✅ 303 to `return_to` |
| `GET /session` returns live meta | ✅ `sub=user-1`, `custody: "ok"` |
| `POST /internal/token` with **both** halves | ✅ returns the upstream access token |
| API key alone (forged session) | ✅ `401 session_not_active` |
| Session token alone (no API key) | ✅ `401 missing_api_key` |
| Custody tokens readable in the DB file | ✅ **No** — absent from `broker.db`/`-wal` |
| Restart with the same cookie | ✅ 1 session rehydrated, cookie still valid |
| Keepalive renews without re-login | ✅ token rotated at ~0.6 × a 20 s TTL, twice |

The last row is the custody claim itself: with `MOCK_IDP_ROTATE_REFRESH_TOKENS=true`
the access token changed underneath a browser session that never re-authenticated.

**Env note:** `localhost` resolves to `::1` on macOS while the broker binds
`127.0.0.1`; use the IPv4 literal or bind `[::1]` when testing by hand.

## What exists

- Project container under `security/session-broker/` following the house
  convention (`AGENTS.md`/`CLAUDE.md`/`CODEX.md`, `.context/`, `docs/`, `repo/`).
- **[Architecture & implementation strategy](../docs/architecture/implementation-strategy.md)**
  — the authoritative design: threat model and invariants, session state machine,
  full HTTP contract, storage model, keepalive worker algorithm, Rust module plan
  with milestones M0–M9, React SDK plan, and test strategy.
- `.context/invariants.md` — INV-1..INV-11, the rules implementation may not break.
- Rust workspace root at `repo/Cargo.toml`, dependency posture aligned with
  `security/iam` and `security/secrets-keeper`.

- `repo/crates/mock-idp` — offline OIDC fixture (authorization-code + PKCE, both
  token grants, JWKS, revocation) with a `/__test__/` control surface including a
  `/token` call counter, so tests can prove INV-8 (refresh never hits the IdP)
  rather than assert it by inspection.
- ADR-0001..0012.
- `session.rs` — the state machine. Proven: rotation keeps the old cookie valid
  through grace; 20 simultaneous refreshes mint exactly one generation; the
  oauth2-proxy concurrent-refresh failure mode passes as a named regression test.
- `http/` — session lane with the CSRF boundary (INV-2) and cookie hardening.
- `keepalive.rs` — pure scheduler (0.6 lead, ±10% jitter, full-jitter capped
  backoff, `Retry-After`) plus revocation propagation.
- `store/`, `config.rs` — SQLite schema, concrete repo, single-writer task.
- `repo/ui/` — standalone pnpm workspace (not part of the outer monorepo's
  `pnpm-workspace.yaml`), React 19 + TS ~5.8:
  - `packages/react-sdk` (`@session-broker/react`) — `meta.ts`/`leader.ts`
    (Web-Lock-held leader election, ADR-0008)/`refresh.ts` (single-flight +
    leader timer + lazy checks)/`fetch.ts` (`brokerFetch`, 401→refresh→retry
    once) + `<SessionProvider>`/`useSession()`. 50 vitest tests (meta
    parsing, single-flight collapse, 401 retry-once, mocked-lock leader
    promotion). `pnpm typecheck`/`build`/`test` all green.
  - `apps/demo` — Vite dashboard: live meta panel, leader badge, the
    forced-race button (raw concurrent `POST /session/refresh`, bypassing the
    SDK's own single-flight so it proves *server* coalescing), refresh log
    (client RTT vs `X-Broker-Handler-Us`), and mock-idp `/__test__/`-backed
    failure controls. `pnpm typecheck`/`build` green.

## In flight

- **M9 as an automated test.** The race and multi-tab behaviours are now
  browser-verified by hand (2026-07-29, below); what is missing is a Playwright
  spec in CI so a regression is caught rather than noticed.

## Decisions worth knowing before you read code

- Storage is embedded SQLite behind one concrete `store::repo` module — **not**
  redb, unlike `security/secrets-keeper`. The HA path is Postgres, and only a
  relational surface ports (ADR-0005).
- Sessions are memory-primary with write-behind; upstream custody is
  write-through. This is only safe *because* rotation is non-invalidating —
  losing a just-minted generation in a crash cannot log anyone out.
- The seven open questions from the architecture pass are resolved in
  [strategy §10](../docs/architecture/implementation-strategy.md); the notable
  default is `on_upstream_revoked = kill`.

## Added since (2026-07-26, later)

- **`/admin/*` + schema v2 (`api_key`).** Backend keys are data now: issued with
  a name, revocable without a restart (the `revoked_at IS NULL` predicate is the
  revocation — no cache to wait out), and stored only as SHA-256. The secret is
  returned exactly once. Verified live: issue → works on `/internal/token` →
  revoke → refused on the next request; and the backend key cannot reach
  `/admin/*` (a key that mints keys is strictly more powerful than one that
  exchanges a session).
- **Console at `repo/ui/apps/console`**, copied from ArrowRef's console. Driven
  in a browser against the running broker: issued a key, saw the one-shot
  secret, listed a live session and a healthy custody.
- **`docs/openapi.yaml`** — the full HTTP contract, 3.1, hand-written because
  what matters is which LISTENER each endpoint is on and what each refusal
  means, neither of which a generator infers.

## Added since (2026-07-27) — observability, both planes

**ADR-0014 (two planes) + ADR-0015 (the durable record).** The service had
`tracing` to stdout and nothing else, which is below the floor now that `/authz`
answers Envoy on every request in the platform. The split that resolves the
latency-vs-audit tension: **diagnostics are lossy and cheap, the audit record is
durable and bounded**, and they want different events.

- **Diagnostics.** `log_format` text|json, optional rolling file sink, both
  through `tracing-appender`'s non-blocking bounded writer — a `tracing::info!`
  on `/authz` costs a channel send, never a `write(2)`. The broker ships nothing
  itself; a sidecar reads stdout. Hand-rolled Prometheus text at `GET /metrics`
  on the internal listener (~20 series, buckets from 50 µs because the refresh
  claim is microseconds), plus one middleware recording per-request metrics keyed
  on the **matched route pattern**, never the raw path.
- **Audit.** Schema v3 `audit` table, `AUTOINCREMENT seq` so a prune cannot hand
  a sequence number back out. **Tier A** rows ride the same `Command::Admin` as
  the mutation and land in the same transaction — a key cannot exist without a
  record of being issued, and a failed transaction refuses the operation.
  **Tier B** is batched with a depth bound; at the bound events drop, the drop is
  counted, and an `audit.gap` row records how many. Hourly prune, 90-day default.
- **Nothing on the hot path writes a row.** `/authz` and `/session/refresh`
  produce metrics only, allow and deny alike. `token.exchanged` coalesces per
  `(key_id, sid)` per 300 s; refusals never coalesce.
- **Console** gains **Audit trail** (filters, `seq` cursor, NDJSON export, and a
  header that says where history starts so an empty result cannot read as
  "nothing happened") and **Observability** (what both planes are doing, copyable
  collector/Prometheus config, and a bounded self-expiring verbosity control).
  The line drawn: the console can change how loud the diagnostics are, never
  where the record goes.
- **INV-12** (no secret material anywhere in telemetry) and **INV-13** (no
  credential change without a committed row; drops are counted and gap-marked).

### Verified by running it

Broker on `:18080`/`:18090` against `mock-idp` on `:19090`:

| Claim | Result |
|---|---|
| Full lifecycle recorded | ✅ `key.issued` → `session.created` → `token.exchanged` → `session.logged_out` |
| A revoke matching nothing | ✅ recorded as `outcome=failure, reason=not_found`, not as a revocation |
| Repeat token exchange | ✅ one row, not two — coalescing works |
| Cookie / admin key / backend key in the log stream | ✅ **absent** (0 hits) |
| Any secret in the audit rows | ✅ **absent** |
| Verbosity: over the ceiling / unparseable filter | ✅ `duration_out_of_range` / `bad_filter`, nothing applied |
| Verbosity change itself audited | ✅ `logging.level_changed`, both raise and restore |
| `/metrics` under real traffic | ✅ per-lane per-route counters, custody gauges, audit counters |
| NDJSON export | ✅ one object per line |

148 crate tests green (was 112), clippy clean under `-D warnings`, console
`typecheck` + `build` green.

## Added since (2026-07-27) — CI/CD

`.github/workflows/ci.yml` (fmt/clippy/test, MSRV 1.88, `cargo audit`, the UI
workspace on a frozen lockfile, `redocly lint` of the contract),
`release.yml` (tagged linux x86_64/aarch64 binaries + console bundle with
checksums; `mock-idp` deliberately excluded from every artifact), and
`dependabot.yml`. `actionlint` clean; every job's commands were run locally
first.

Two decisions worth knowing:

- **`cargo audit` blocks**, and the one exception —
  `RUSTSEC-2023-0071` (`rsa`, no fix available, reached via `openidconnect`) —
  is recorded in `repo/.cargo/audit.toml` with the reason it does not apply: the
  broker holds no RSA private key and only *verifies* RS256 ID tokens; the only
  private key in the tree belongs to `mock-idp`, a dev-dependency.
- **`redocly.yaml`** turns off four rules as decisions with reasons, so a
  warning from that job means something.

**Three real bugs surfaced on the first runs**, which is the argument for the
jobs existing:

1. **`docs/openapi.yaml` was invalid.** `nullable: true` is OpenAPI 3.0 syntax
   in a file declaring 3.1, and several inline flow mappings had unquoted commas
   that YAML parsed as extra keys.
2. **`react-sdk` tests used `Buffer`**, a Node global the browser package never
   declared. It typechecked against a hoisted `@types/node` in a local store and
   failed on a clean `--frozen-lockfile` install. Fixed by encoding the way the
   SDK *decodes* — `btoa`/`TextEncoder` in `__tests__/base64url.ts`, mirroring
   `meta.ts`'s `base64UrlDecode` — rather than by adding a Node typing to a
   browser package.
3. **The console and demo Vite configs used `node:path`/`process`/`__dirname`
   without declaring `@types/node`.** The opposite fix to (2), for the opposite
   reason: a Vite config genuinely runs in Node, so the typing was declared.
   Same symptom, different bug — worth not conflating.

All five jobs green on
[PR #1](https://github.com/jamiepearcey/session-broker/pull/1).

## Added since (2026-07-28) — gaps closed, and two bugs the tests found

The four gaps listed after the observability work are closed:

- **`custody.degraded`/`custody.dead`/`custody.revoked_upstream`** are emitted by
  the keepalive worker, once per **transition** rather than per retry. The guard
  has a mutation-tested case behind it — 4 rows without it, 1 with.
- **`login.failed`** carries a stable `OauthError::code()` rather than the
  error's `Display`, which embeds provider-supplied strings: attacker-influenced,
  unbounded, and impossible to group by.
- **`broker_keepalive_refresh_total` / `_upstream_duration_seconds`** are
  observed, timed around the upstream call only.
- **INV-12 has a log-stream test.** The audit-row half was already tested; this
  installs a scoped subscriber over an in-memory writer and greps the bytes. It
  has a positive control, which is what made it useful — see below.

**Two real bugs, both found by the new tests rather than by reading:**

1. **`emit_to_log` dropped `client_ip_prefix` and `detail`.** The log-stream
   archive was strictly poorer than the store's 90-day window, which falsifies
   ADR-0014's claim that the stream *is* the archive. Caught by the redaction
   test's positive control — the assertion that permitted identifiers ARE
   present, without which the test would pass against a subscriber emitting
   nothing.
2. **Custody failures were never persisted.** Nothing sent
   `CustodyWrite::Failure`, so `repo::update_custody_failure` was unreachable and
   the durable row never left `status='ok', fail_count=0` however many refreshes
   failed. `live_custody_schedules`' `status != 'dead'` filter could therefore
   never match: a dead grant came back alive on every boot with its backoff
   reset. `/admin/custody`, the Custody console view and the brand-new
   `broker_custody{status}` gauge all read those rows, so all three reported
   healthy grants that were not — the exact symptom the Custody view exists to
   surface. The worker now persists health and backoff on every failure,
   fire-and-forget: no token rotates on a failure, so §6's write-through hazard
   does not apply, and an ack per failure would serialise the whole fleet behind
   one fsync during precisely the outage that produces them.

### Verified by running it

| Claim | Result |
|---|---|
| `login.failed` with distinct reasons | ✅ `no_txn_cookie`, `state_mismatch` |
| IdP killed under a live session | ✅ one `custody.degraded`, not one per retry (5 transients) |
| Fresh IdP instance rejects the old grant | ✅ `custody.dead`, then `custody.revoked_upstream` `{policy: kill, sessions_killed: 1}` |
| Keepalive metrics populate | ✅ `success` / `transient` / `permanent` + latency histogram |
| Durable custody row tracks reality | ✅ `status=degraded fail_count=2`, and `/admin/custody` agrees |

152 crate tests green, clippy clean under `-D warnings`.

## Added since (2026-07-28/29) — dependencies taken, and a filter bug found by running it

All 11 pending Dependabot updates applied on one branch (they shared lockfiles,
so individually they would have been ten rebases). Notes worth keeping:

- **`rand` 0.10 renamed `OsRng` → `SysRng` and made it fallible (`TryRng`).**
  Rather than fix five call sites separately, all secret material now goes
  through one `token::fill_random` — the INV-5 boundary in one reviewable place.
  It panics on entropy failure deliberately: a token or key from a degraded
  source fails open, silently, and nothing downstream can tell.
- **`jsonwebtoken` 11 requires the crypto provider chosen explicitly** and
  panics at *first use*, not at build time. Took `rust_crypto`, matching the
  workspace's existing `rustls-tls` posture.
- **`mock-idp` is pinned to `rand` 0.8** because `rsa` still wants rand_core
  0.6. Pinning the fixture keeps the broker current, and the fixture ships in no
  release artifact.
- **Dependabot rewrote the pinned MSRV.** It read
  `dtolnay/rust-toolchain@1.88.0` as an action version and bumped it to
  `@1.100.0`, silently converting the `msrv` job into a duplicate of the main
  one. The toolchain is now a `with:` value and `dependabot.yml` ignores that
  action.

**The bug running it found — `EnvFilter` matches the TARGET, not the crate.**
This service's events carry explicit targets (`broker::audit`, `broker::http`,
`broker::authz`, `broker::telemetry`), so the default
`session_broker=info,tower_http=warn` matched every module-path event and
**silently dropped every named one — including the audit stream**. ADR-0014
calls that stream the long-term archive, so a deployment shipping to a SIEM for
long retention was archiving nothing. Fixed in the config default,
`LogConfig::default` and the console presets, with a test that fails against the
old value.

Why nothing caught it: the redaction test installs a subscriber with
`max_level(TRACE)` and no `EnvFilter`, so it exercises the formatter, not the
filter. **Testing what a sink writes says nothing about whether anything reaches
the sink.**

### Verified by running it (full stack, updated deps)

| Claim | Result |
|---|---|
| Login → session → `/internal/token` | ✅ |
| INV-5: upstream token findable in `broker.db` | ✅ **No** — sealed under chacha 0.11 |
| Refresh coalescing | ✅ 3 coalesced, ~0.6 ms handler time |
| Keepalive rotates the upstream token, no re-login | ✅ token changed under a live session |
| Console (vite 8) Audit trail + Observability | ✅ browser-driven |
| Verbosity raise → audited → self-restores | ✅ both changes recorded, gauge back to 0 |
| `broker::audit` reaching the log stream | ✅ after the fix; 1 line across a whole lifecycle before |

153 crate tests, clippy clean, CI green on `main`.

## Added since (2026-07-29) — the reaper (M6)

Nothing removed dead rows. `Command::DeleteExpiredTxns` was handled by the
writer but never sent, `SessionMap::sweep` was called only from tests, and there
was **no SQL at all** to delete tombstoned sessions or their generations — the
same shape as the custody-failure bug: machinery that exists, wired to nothing.
`live_custody_schedules`' filter and the txn TTL were both inert for the same
reason.

- **Schema v4** adds `session.tombstoned_at`. A retention policy needs the
  timestamp of the event it retains from, and `tombstone_session` recorded only
  `status`. `COALESCE` keeps the FIRST death, so a client retrying an idempotent
  logout cannot keep a dead row alive by pushing its timestamp forward.
- **`repo::reap`** is the only place that deletes session/generation/txn/custody
  rows, on three independently-safe predicates (tombstoned past the window;
  `absolute_exp` past the window; txn past INV-3's 10 minutes). A NULL
  `tombstoned_at` from before v4 falls through to `absolute_exp` rather than
  being treated as old — guessing old on a delete path is the wrong direction to
  be wrong in.
- **Orphaned custody rows go too**, which shrinks the credential material at
  rest: a custody no session references holds an encrypted refresh token nobody
  can ever use.
- A task sweeps **both memory and disk** every 10 minutes. Neither substitutes
  for the other — memory is rebuilt from disk on restart, and disk is never
  re-read while running.

The "a live session survives every sweep" test is mutation-checked: inverting
the `absolute_exp` guard fails it.

### Verified by running it

3 logins, 2 logouts, restart → reaper removed 2 sessions, 2 generations and 2
orphaned custodies; the live session survived and still answered `/session`;
`txn` emptied. And **5 audit rows still describe all 3 sessions with only 1
session row left** — the store keeps a working set, the audit record keeps the
history.

160 crate tests, clippy clean.

## Added since (2026-07-29) — the demo, verified in a browser at last

Every claim in `repo/ui/apps/demo` had only ever run against mocked
`fetch`/`navigator.locks`. Driven against a live broker + mock-idp:

| Claim | Result |
|---|---|
| Login through the SPA, all three clocks | ✅ 10 min gen / 7 d idle / 30 d absolute |
| **Forced race — the headline property** | ✅ 20 concurrent → **20 succeeded, 0 failed, 1 generation minted**, 11.2 ms |
| Web Lock leader across two tabs | ✅ exactly one leader |
| Promotion when the leader closes | ✅ survivor promoted and opened the SSE stream (ADR-0008) |
| `session.killed` over SSE | ✅ admin revoke → `admin_revoked`, tab flipped to Expired instantly (ADR-0013) |
| Stale cookie from a previous broker instance | ✅ 401 → cleared → anonymous, no wedged state |

So ADR-0002 (non-invalidating rotation removes the refresh race), ADR-0008 (one
Web Lock, no coordination traffic) and ADR-0013 (SSE as a hint) are now each
demonstrated end to end rather than argued.

One fix fell out: **both Vite dev servers bind `127.0.0.1` explicitly.** Vite
defaults to `localhost`, which is `::1` on macOS, while the broker binds IPv4 —
so a login built from `base_url` bounced off ERR_CONNECTION_REFUSED while the
same page loaded fine over `localhost`. The proxy *targets* in those configs
already carried a comment about exactly this; the server's own bind did not.

## Added since (2026-10-03) — production hardening (ADR-0016)

The POC gaps: nothing bounded guessing, requests had no size/time limits, SIGTERM
lost the write-behind queue, `/healthz` could not say the store was dead, and the
custody key could not be rotated.

- **Rate limiting** (M6, finishing earlier WIP): wrong admin/backend keys keyed on
  the peer; `/auth/login` keyed on a configured client-IP header and **off
  without one** (behind an edge every request shares a peer).
- **`http::hardening`**: 64 KiB body ceiling, 30 s handler deadline (SSE exempt),
  `no-store`/`nosniff`/CSP/`X-Frame-Options`/CORP, HSTS iff `base_url` is https.
- **Graceful drain**: SIGTERM → `/readyz` 503 → `shutdown_drain_delay_secs` →
  stop accepting → wait ≤ `shutdown_grace_secs` → writer flushed.
- **`GET /readyz`** (internal): not draining + writer alive + store answers.
- **Custody keyring**: sealed = `01 || key_id || nonce || ct`, AAD = header +
  `custody:<id>:<column>`; `session-broker rotate-key`; boot-time `Reseal` moves
  rows to the active key inside the writer transaction. Keyfile with group/other
  bits is now refused (the module docs claimed this; the code did not).
- **Config**: `oidc_client_id` required with an issuer; `oidc_redirect_uri`
  defaults to `<base_url>/auth/callback` (previously an unset one failed at the
  first login with `NotConfigured`).
- **`repo/Dockerfile`**, distroless, non-root, state in `/data`.

**Breaking:** sealed values written before this have no header and will not
open — delete development databases. The keyfile format is backward compatible.

### Verified by running it

| Claim | Result |
|---|---|
| Hardening headers on the public lane | ✅ all present, no HSTS on http |
| `/readyz` | ✅ 200 → **503 `draining:true`** after SIGTERM, before the listener closes |
| Oversize body | ✅ 413 (200 KB to `/admin/api-keys`) |
| Admin brute force | ✅ 10×401 then 429 |
| Drain with an SSE stream held open | ✅ exits at delay + grace (4.09 s), logs the forced close |
| `rotate-key` + restart | ✅ `resealed=1`; raw column header `01 02`; same `/internal/token` access token still served |

189 crate tests, clippy clean under `-D warnings`.

## Added since (2026-10-11) — token issuer, slice S1: signing core and schema v5

First of seven slices (`docs/design/token-issuer-scope.md` is the scope;
`token-issuer.md` the fuller design it overrides). Nothing issues a token yet:
this slice is the keys and the signer.

- **Schema v5**, one migration: `tenant` (a `default` row pre-seeded),
  `principal`, `principal_secret`, `user_grant`, `signing_key`. Only
  `signing_key` has code behind it so far.
- **`issuer/`**: Ed25519 keys in the store, seed sealed under the custody
  keyring (AAD `signing:<kid>:seed`); a compact-JWS signer (`alg=EdDSA`,
  `typ=JWT`); an in-memory key cache that re-reads the store every 60 s.
  `kid` = base64url(SHA-256(public key)[..8]).
- **No state column.** Pending / signing / published are derived from
  `activate_at` / `retire_at` / `removed_at` against the clock.
- **First boot creates one key** with a Tier A `signing_key.created` row. From S3
  this happens only when the issuer is configured (`token_issuer` and
  `issuer_audiences`); an unconfigured broker creates no key.
- **Rotation is an operation**: `POST /admin/signing-keys/rotate`
  (`{"activate_in_secs": N}`, default a day) and
  `session-broker rotate-signing-key [--now]`. Zero lead = emergency: the new key
  signs now and every older key is unpublished now.
- **Prune** rides the hourly audit-prune timer and marks keys past `retire_at`
  removed (`signing_key.removed`). It runs even with `audit_retention_days = 0`.
- **Boot `Reseal` now covers `signing_key.seed_sealed`** as well as custody.
- `ed25519-dalek` is a direct dependency (it was already in the graph);
  `jsonwebtoken` is a dev-dependency of the broker, so tokens are verified in
  tests by code that shares nothing with the encoder.

**One bug found by running it, not by the tests:** after a rotation with a lead,
an emergency rotation left the original key published for two more days — the
UPDATE only dated keys with `retire_at IS NULL`. It now also pulls an earlier
date onto keys dated later, with a regression test.

206 crate tests (was 189), clippy clean under `-D warnings`.

## Added since (2026-10-11) — token issuer, slice S2: tenants, principals, grants

Identities as data on the admin lane (`http/admin/identity.rs`), same admin-key
guard as the rest of `/admin/*`; every mutation is Tier A. No tokens are issued
yet — nothing resolves a principal secret until S4.

- **Routes**: `GET|POST /admin/tenants`, `DELETE /admin/tenants/{tenant}`
  (disable), `POST /admin/tenants/{tenant}/enable` (undo it; Tier A
  `tenant.enabled`); `GET|POST /admin/principals` (`?tenant=`),
  `GET|DELETE /admin/principals/{id}`; `POST /admin/principals/{id}/secrets`,
  `DELETE /admin/principals/{id}/secrets/{secret_id}`; `GET|POST
  /admin/user-grants` (`?tenant=&sub=`), `DELETE /admin/user-grants/{sub}/{tenant}`;
  `GET /admin/signing-keys` (derived `pending|signing|published|retired|removed`).
  They work whether or not the issuer is configured; only rotation needs it.
- **Secrets**: `sbp_` + 32 random bytes (base64url), shown once, SHA-256 of the
  whole string at rest. **No expiry by default.** Creating a principal returns
  its first secret; adding one leaves the older ones valid. Optional
  `expires_in_secs` dates the new secret; optional `expire_old_in_secs` dates the
  older live ones (never later than they already were; `0` is now). Ids: `sp_`
  principals, `sps_` secrets.
- **No tenant step**: naming a tenant slug in a principal or grant creates it in
  the same transaction. A disabled tenant refuses new principals and grants and
  its principals stop resolving. A revoked principal keeps its name (the
  `UNIQUE (tenant_id, name)` from v5).
- **`repo::find_live_principal_by_secret(conn, hash, now)`** is the lookup S4
  will use: secret not revoked and not past `expires_at`, principal not revoked,
  tenant not disabled. Tests drive the clock across each term.
- **Grants** are keyed `(sub, tenant)`: a revoked grant is revived in place by
  creating it again; a live one is a 409.
- Unapplied creates (name taken, grant live, tenant disabled) answer 409 and
  leave a `failure` audit row with reason `conflict`; unapplied revokes 404.
- Not audited on their own: a tenant created implicitly by a principal or grant.
  It rides inside that row's transaction and shows in `GET /admin/tenants`.

## Added since (2026-10-11) — token issuer, slice S3: publication and config

The issuer is on only when `token_issuer` and `issuer_audiences` are both set
(one without the other is a startup error). Off, no signing key is created and
both documents answer `501 lane_disabled`.

- **Routes (public listener)**: `GET /auth/jwks.json` (every published key,
  pending ones included) and `GET /.well-known/oauth-authorization-server`
  (`issuer`, `jwks_uri`, `response_types_supported`; the token endpoint is added
  by S4). Both send `Cache-Control: public, max-age=<issuer_jwks_max_age_secs>,
  stale-if-error=2592000`, an `ETag` (304 on `If-None-Match`) and a `Date`. The
  hardening layer only adds `no-store` when a handler set no `Cache-Control`, so
  these are untouched; a test runs them through that layer.
- **Config** (`BROKER_*` or the file): `token_issuer` (equal to `base_url` or a
  URL under it, no query or fragment, trailing slash dropped), `issuer_audiences`
  (comma list), `issuer_machine_ttl_secs=86400`, `issuer_user_ttl_secs=3600`,
  `issuer_max_ttl_secs=2592000`, `signing_key_publish_lead_secs=86400`,
  `issuer_jwks_max_age_secs=300`. The TTLs must be 1..=`issuer_max_ttl_secs`
  (itself 1..=365 days); the lead 1..=30 days. `jwks_uri` is `base_url` +
  `/auth/jwks.json`. `BrokerConfig.issuer: Option<IssuerConfig>`;
  `IssuerConfig::key_policy()` feeds `bootstrap`, the rotate route and the CLI.
- **No `issuer_allow_plaintext`, no introspection setting.** An `http://` issuer
  off loopback logs one warning at start and is allowed. (`base_url` itself is
  still refused off loopback over http by `HttpConfig::new`, so today that warning
  can only fire if that rule is relaxed.)
- **Wiring**: `AppState.issuer: Option<IssuerHandle { signer, config }>`;
  `AdminState.issuer` keeps the bare `Arc<Issuer>`.

## Added since (2026-10-11) — token issuer, slice S4: machine tokens

`POST /auth/token` on the public listener: a service principal trades its secret
for a signed token (OAuth client credentials). `501 lane_disabled` until the
issuer is configured.

- **Request**: `application/x-www-form-urlencoded` only.
  `grant_type=client_credentials`, `client_id` (the `sp_` id), `client_secret`
  (the `sbp_` secret), optional `scope` (space-separated, a subset of the
  principal's) and optional `ttl` (seconds, at most the principal's
  `max_ttl_secs` and `issuer_max_ttl_secs`). The id and secret may come in HTTP
  Basic instead; both at once is `invalid_request`. Unknown fields, `tenant` and
  `audience` among them, are ignored.
- **Response**: `{access_token, token_type: "Bearer", expires_in, scope}`,
  `no-store`. Default lifetime is `issuer_machine_ttl_secs`, lowered to the
  principal's maximum.
- **Claims**, all from the principal's row: `iss`, `sub` (principal id), `aud`
  (one string), `exp`, `iat`, `jti`, `tenant`, `kind`, `name`, `scopes`,
  `indexes`. Header `alg=EdDSA`, `typ=JWT`, `kid`.
- **Refusals** are `{error, error_description}`: `invalid_request` 400 (not a
  form, missing `grant_type`, a parameter sent twice, bad or too-long `ttl`),
  `unsupported_grant_type` 400, `invalid_client` 401 with `WWW-Authenticate`
  (one identical body for an unknown id, a wrong, revoked or expired secret, a
  revoked principal, a disabled tenant), `invalid_scope` 400,
  `unauthorized_client` 400 (the principal's audience is not in
  `issuer_audiences`), `rate_limited` 429 with `Retry-After`,
  `temporarily_unavailable` 503 (store unreadable or no signing key),
  `lane_disabled` 501.
- **Rate limit**: wrong credentials only, one bucket per `client_id`
  (`rate_limit_auth_failure_burst` per `rate_limit_auth_failure_per_secs`, off
  with `rate_limit_enabled=false`). It does not depend on a client-IP header.
  The budget is spent after the check, so the holder of the right secret is
  never locked out by someone guessing against its id. There is no limit on
  successful issuance.
- **`last_used_at`** on the principal is written at most once a minute per
  principal (`AdminWrite::TouchPrincipal`, sent by `Issuer::record_use`).
- **Audit** (Tier B): `token.issued`, one row per (principal, audience) per
  `audit_coalesce_secs`, detail `{aud, kind, tenant, kid, jti, ttl}`;
  `token.issuance_refused`, one row per refusal, reason = the error code. Not
  recorded: a request that names no credential (counted in the metric only), a
  429, a 501, a 503.
- **Metric**: `broker_tokens_issued_total{kind,outcome}`; `kind` is the
  principal's kind, or `machine` before the caller is identified.
- **Metadata** now carries `token_endpoint`, `grant_types_supported` and
  `token_endpoint_auth_methods_supported`.
- An issued token cannot be revoked. Revoking the principal or the secret stops
  the next one.

### S5: user tokens (`POST /session/token`)

A signed-in user trades their session for a signed token. Public listener,
`501 lane_disabled` until the issuer is configured.

- **Request**: cookie-authenticated, JSON `{"audience", "tenant"?}`. INV-2 runs
  first (`403 csrf_rejected`). The session must be `Active`, exactly as `/authz`
  requires: no cookie or an unknown one is `401 invalid_session`, a stale
  generation `401 session_stale` (refresh, retry), an expired or logged-out
  session `401 session_expired`.
- **Response**: `{access_token, token_type: "Bearer", expires_in, tenant, roles,
  indexes}`, `no-store`. Lifetime is `issuer_user_ttl_secs`, cut short at the
  session's idle expiry.
- **Claims**: `iss`, `sub` (the identity provider subject), `sid` (the broker
  session id, never the cookie), `aud`, `exp`, `iat`, `jti`, `kind: "user"`,
  `tenant`, `roles`, `indexes`. Header `alg=EdDSA`, `typ=JWT`, `kid`.
- **Tenant, roles and indexes come only from `user_grant`** for the subject
  (`repo::find_live_user_grants`: not revoked, tenant not disabled). One grant:
  `tenant` may be omitted. Several and no `tenant`: `400 bad_request`. A tenant
  with no grant: `403 not_granted`. `audience` must be in `issuer_audiences`:
  `400 bad_audience`.
- **Single-tenant default** (scope addendum): a subject the table has never held
  a row for gets `default_user_tenant` (default `default`) with
  `default_user_roles` (default `viewer`) and `indexes: ["*"]`. `none` (or empty
  in the file) turns it off. A subject whose grants were all revoked, or sit in
  a disabled tenant, is NOT rescued by the default: `403 not_granted`.
- **`/internal/token` is unchanged** (the scope addendum dropped the opt-in
  `token_type: "broker"`), as is `/authz`.
- **Audit** (Tier B, actor `user`): `token.issued` carries `subject` and `sid`,
  detail `{aud, kind, tenant, kid, jti, ttl}`, coalesced per (subject, audience)
  per `audit_coalesce_secs`; `token.issuance_refused` once a user is known
  (reason = the error code), never coalesced. A forged or cookie-less request is
  counted in the metric only. `broker_tokens_issued_total{kind="user",outcome}`.

## Added since (2026-10-11) — token issuer, review fixes

- **Rotation overlap (ISS-1).** `rotate_signing_key` also unpublishes, at `now`,
  any key that has not started and would activate after the new one, so an
  earlier, slower rotation cannot take signing back from a later, faster one.
- **Default tenant (ISS-2).** The `default_user_tenant` fallback on
  `POST /session/token` answers `not_granted` when that tenant is disabled.
- **Failure limiter (ISS-3).** `/auth/token` gives a budget of its own only to
  an id that names a principal row; every other id shares one `unknown` bucket,
  so refusals and their audit rows are bounded by the limiter.
- **Tenant enable (ISS-4).** `POST /admin/tenants/{tenant}/enable`
  (`AdminWrite::EnableTenant`, sent by that handler only).

## Added since (2026-10-11) — token issuer, slices S6 and S7: console, contract, verifier

- **Console (S6)**: Principals (tenant filter, create form, one-shot secret panel,
  add and revoke secrets, revoke principal), User grants and Signing keys views in
  `repo/ui/apps/console`, over the admin lane. Merged from `wf/issuer-console`;
  the only overlap was `lib/api.ts`, which merged without conflict.
- **ADR-0017** records the decision: the broker becomes a token issuer, amending
  ADR-0001 (it holds tenants, principals and grants as data but still evaluates no
  policy and is not an IdP) and ADR-0006 (sessions stay opaque; a JWKS now exists
  for the tokens it signs). It also holds the "deliberately not built" list and the
  honest limits from `docs/design/token-issuer-scope.md`.
- **`docs/openapi.yaml`**: tag `issuer`, every new path (`/auth/token`,
  `/auth/jwks.json`, `/.well-known/oauth-authorization-server`, `/session/token`,
  and the `/admin/{tenants,principals,user-grants,signing-keys}` family), their
  schemas, the `principalSecret` scheme. `/internal/token` is NOT extended (the
  scope addendum dropped `token_type: "broker"`); its description says so.
  `ApiError` was documented as `{code, message}`; the code has always sent
  `{error, detail, login_url?}`, so the schema now says that.
- **INV-12 and INV-13 reworded** for principal secrets, seeds, issued tokens, grants,
  tenants and signing keys; `docs/architecture/observability.md` lists the new audit
  actions and `broker_tokens_issued_total`.
- **Verifier (S7)**: `docs/verifier/README.md` (the checks in order; clock allowance
  300 s; key cache refreshed hourly, served from cache without a time limit while the
  broker is unreachable) and `docs/verifier/vectors.json`, generated by
  `issuer::vectors` from a fixed test-only seed (the seed is public in that source
  file). The test fails if the committed file differs from what the signer produces;
  `UPDATE_VECTORS=1 cargo test -p session-broker vectors` regenerates it. The same
  test runs every vector through a reference verifier written from the README, so the
  expected verdicts are checked rather than asserted.
- **README** has a "create a principal, get a token" section with curl.

## Known gaps that remain

- **Postgres/HA backend** (ADR-0005): readiness and drain make ONE node well
  behaved; they are not high availability.
- **The `/proxy/*` browser lane is not built** (ADR-0007's other half). Nothing
  needs it: backends use `/internal/token`.
- **Login transactions are in-memory.** A restart mid-login costs one retry.
- **INV-6a concurrent-IP anomaly** needs a per-generation `client_ip_prefix`.
- **M9 as a CI Playwright spec** — browser-verified by hand, not automated.

## Not built, deliberately

- Subdomain/CORS topology (v1 is single-origin path-mounted, INV-10).
- Postgres/HA backend (the surface is designed for it; the code is not written).
- Any identity-provider behaviour: no user store, no credentials, no policy engine.
