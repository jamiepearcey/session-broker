# Current State

_Last updated: 2026-07-26_

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

- Browser verification of `repo/ui/` against the now-running broker (M9).

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

## Known gaps that remain

- **The `/proxy/*` browser lane is not built.** ADR-0007's other half. Nothing
  currently needs it: backends use `/internal/token`, and the platform's chosen
  topology routes data traffic directly rather than through the broker.
- **The reaper (M6) does not run.** Tombstoned sessions and expired txn rows
  accumulate on disk. They are inert — `rehydrate` loads only `alive` rows —
  but the file grows without bound.
- **Login transactions are still in-memory.** A restart mid-login costs one
  retry.
- ~~Three catalogued audit actions declared but not emitted~~ — **closed
  2026-07-28.** All of `custody.*` and `login.failed` are emitted, and the
  keepalive metric families are observed. See below.

## Not built, deliberately

- Subdomain/CORS topology (v1 is single-origin path-mounted, INV-10).
- Postgres/HA backend (the surface is designed for it; the code is not written).
- Any identity-provider behaviour: no user store, no credentials, no policy engine.
