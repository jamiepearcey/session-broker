# Current tasks

Milestones are defined in
[implementation-strategy.md §7](../architecture/implementation-strategy.md).
⚙ = mechanical/delegatable, ★ = needs care.

## In progress

- [x] Project container, README, project brief, invariants
- [x] Architecture & implementation strategy (architect pass documented)
- [x] ADR-0001..0012 written up from the strategy doc
- [x] `crates/mock-idp` — offline OIDC fixture with `/__test__/` control surface
      (10 tests). Its `/token` call counter is what makes INV-8 provable.
- [x] **M1 ★** `session.rs` pure state machine + property tests
- [x] **M0 ⚙** config, store schema/migrations, repo, writer task
- [x] **M3 ⚙** HTTP session endpoints + cookie/CSRF guards + meta cookie
- [x] **M4 ★** keepalive scheduler, backoff/jitter, revocation propagation
- [x] **M2 ★** OAuth login/callback against the mock IdP (INV-3/INV-4 negatives)
- [x] **M7 ★** React SDK (`@session-broker/react`) — `repo/ui/packages/react-sdk`,
      standalone pnpm workspace at `repo/ui/`. Typecheck/build/vitest (29 tests)
      all green. Not yet exercised against a running broker (blocked on M2 +
      `main.rs` wiring below).
- [x] **M8 ⚙** demo app — `repo/ui/apps/demo` (Vite + React 19). Dev proxy wired
      to the broker + mock-idp `/__test__` surface; forced-race button issues
      raw concurrent `POST /session/refresh` calls (bypassing the SDK's
      single-flight on purpose, to exercise server-side coalescing). Unverified
      end-to-end — see "Known gaps" below.

- [x] `main.rs` wiring: config → store → rehydrate → session map → custody +
      keepalive → two listeners. Session/generation writes go through
      `SessionMap::with_durability`; custody is write-through on the callback
      path and renewed by the keepalive worker (`custody::OidcUpstream`).
- [x] **M5a ⚙** `/internal/token` (INV-11 dual auth), on its own listener.
- [x] **M10 ⚙** `/admin/*` — API keys (issue/list/revoke, one-shot secret,
      SHA-256 at rest), sessions (list/force-logout), custody health. Guarded by
      a SEPARATE `admin_api_key`, on the internal listener. Schema v2 adds
      `api_key`, so backend credentials are now data rather than one static
      config value: nameable, revocable without a restart, and the config key
      demotes to a bootstrap/break-glass credential.
- [x] **Console** — `repo/ui/apps/console` (port 5181), derived from ArrowRef's
      console (`infrastructure/query-cache/repo/ui`): same token set, badge
      register and rail. Three views: API keys, Sessions, Custody. The admin key
      is held in memory for the tab only, never persisted.
- [x] **OpenAPI** — `docs/openapi.yaml` (3.1), all paths across the three
      lanes, with what each refusal MEANS rather than just its status.

- [x] **Observability, both planes (ADR-0014/0015).** Diagnostics: non-blocking
      stdout (JSON or text) plus an optional rolling file sink, hand-rolled
      Prometheus exposition at `GET /metrics` on the internal listener, and one
      metrics+log middleware keyed on the MATCHED route. Audit: schema v3
      `audit` table, Tier A carried inside the same writer transaction as the
      mutation it records, Tier B batched with a depth bound and honest
      `audit.gap` markers, hourly retention prune (default 90 days),
      `GET /admin/audit` with filters/cursor/NDJSON export. Console gains
      **Audit trail** and **Observability** views, including a bounded,
      self-expiring verbosity control. INV-12/INV-13 added.

- [x] **CI/CD (GitHub Actions).** `ci.yml` — fmt/clippy/test, an MSRV check
      against the 1.88 the manifest claims, `cargo audit` (blocking, with
      exceptions recorded in `repo/.cargo/audit.toml` and each carrying its
      reason), the UI workspace against a frozen lockfile, and a `redocly lint`
      of the hand-written OpenAPI. `release.yml` — tagged linux x86_64/aarch64
      binaries + console bundle with checksums, mock-idp deliberately excluded.
      `dependabot.yml` — grouped weekly cargo/npm, monthly actions.

      Three real bugs surfaced on the first runs and are fixed: the OpenAPI
      spec was **invalid** (3.0's `nullable: true` in a 3.1 file, plus unquoted
      commas in inline flow mappings); `react-sdk` tests built fixtures with
      Node's `Buffer` in a browser package (now `btoa`/`TextEncoder`, mirroring
      how `meta.ts` decodes); and the console/demo Vite configs used Node APIs
      without declaring `@types/node` (declared — a Vite config really does run
      in Node, which is the opposite call to the `Buffer` one).

## Next

- [ ] **M5b ⚙** the `/proxy/*` browser lane. Deliberately deferred: the
      platform routes data traffic directly to services, which authenticate
      via `/internal/token`, so nothing needs the proxy today.
- [ ] **M6 ⚙** reaper task, rate limiting. *(Anomaly events are now recorded:
      superseded- and retired-generation use emit `session.anomaly` rows and
      `broker_session_anomalies_total`. The remaining INV-6a signal — two
      generations used concurrently from different IP prefixes — needs the
      per-generation `client_ip_prefix` the `session.meta` column was reserved
      for, and is not wired.)*
- [ ] **M9 ★** race/multi-tab harness (concurrency + Playwright)
- [ ] Browser verification of `repo/ui/` against the running broker

## Known gaps, stated plainly

- ~~`store::seal`/`open` are identity functions~~ — **INV-5 is met.**
  `store::crypto` is XChaCha20-Poly1305 under a keyfile key loaded by
  `store::open`, so there is no reachable state in which a caller holds a
  `Connection` whose custody columns would be written in plaintext. Confirmed
  by grepping the live database file for a known access token: absent.
- Login transactions are in-memory; a restart mid-login costs one retry. The
  durable `txn` table exists in the store for when that matters.
- The keepalive worker's async runner is exercised via `tick()`; the sleep loop
  around it is not yet driven by a test.
- The React SDK and demo app (`repo/ui/`) are built and unit-tested in isolation
  only. There is no bootable `session-broker` binary yet (`main.rs` wiring is
  still on the "Next" list) and OAuth login/callback (M2) isn't built, so the
  demo's live panel, leader promotion across real tabs, forced-race button, and
  failure-path controls have not been exercised against a running broker —
  only against mocked `fetch`/`navigator.locks` in the SDK's own tests.

## Closed since (2026-07-28)

- [x] **The observability gaps are closed.** `custody.degraded`/`custody.dead`/
      `custody.revoked_upstream` are emitted by the keepalive worker, once per
      TRANSITION rather than per retry (a guard with its own mutation-tested
      case: 4 rows without it, 1 with). `login.failed` is emitted with a stable
      low-cardinality `OauthError::code()` rather than its `Display`, which
      carries attacker-influenced provider strings. `broker_keepalive_*` metrics
      are observed. INV-12 now has a **log-stream** test, not just a row test.

- [x] **Two real bugs the new tests found, both fixed:**
      1. `AuditSink::emit_to_log` dropped `client_ip_prefix` and `detail`, so the
         log-stream archive was strictly poorer than the store's own copy —
         which falsified ADR-0014's claim that the stream *is* the long-term
         archive.
      2. **Custody failures were never persisted.** Nothing sent
         `CustodyWrite::Failure`, so `repo::update_custody_failure` was
         unreachable and the durable row never left `status='ok',
         fail_count=0`. Consequences: `live_custody_schedules`' `status != 'dead'`
         filter could never match, so a dead grant was restored alive with its
         backoff reset; and `/admin/custody`, the Custody console view and the
         new `broker_custody{status}` gauge all reported healthy grants that were
         not. The worker now persists health and backoff on every failure,
         fire-and-forget (no token rotates on a failure, so §6's write-through
         hazard does not apply, and an ack per failure would serialise the whole
         fleet behind one fsync during an outage).

- [x] **Dependencies current (2026-07-29).** All 11 Dependabot PRs applied and
      merged; the majors needed real work (see `.context/current-state.md`).
      Running the result found that `EnvFilter` matches the event TARGET, not
      the crate — so the default filter had been silently dropping every
      `broker::*` event, audit stream included. Fixed with a test that fails
      against the old default.

## Deferred

- Subdomain/CORS topology (INV-10 keeps v1 path-mounted)
- Postgres/HA backend (surface is designed for it; not built)
