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
- [x] **OpenAPI** — `docs/openapi.yaml` (3.1), all 12 paths across the three
      lanes, with what each refusal MEANS rather than just its status.

## Next

- [ ] **M5b ⚙** the `/proxy/*` browser lane. Deliberately deferred: the
      platform routes data traffic directly to services, which authenticate
      via `/internal/token`, so nothing needs the proxy today.
- [ ] **M6 ⚙** reaper task, anomaly events, rate limiting
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

## Deferred

- Subdomain/CORS topology (INV-10 keeps v1 path-mounted)
- Postgres/HA backend (surface is designed for it; not built)
