# Current State

_Last updated: 2026-07-26_

## Status

_Updated 2026-07-26._ **The broker boots and has been driven end to end against
a running mock IdP.** M0–M5a are implemented and green (112 crate tests + 10 in
`mock-idp`, clippy clean under `-D warnings`). M7 (React SDK) and M8 (demo app)
are implemented and unit-tested in isolation (`repo/ui/`, 29 vitest tests) but
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
    once) + `<SessionProvider>`/`useSession()`. 29 vitest tests (meta
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

## Known gaps that remain

- **The `/proxy/*` browser lane is not built.** ADR-0007's other half. Nothing
  currently needs it: backends use `/internal/token`, and the platform's chosen
  topology routes data traffic directly rather than through the broker.
- **The reaper (M6) does not run.** Tombstoned sessions and expired txn rows
  accumulate on disk. They are inert — `rehydrate` loads only `alive` rows —
  but the file grows without bound.
- **Login transactions are still in-memory.** A restart mid-login costs one
  retry.

## Not built, deliberately

- Subdomain/CORS topology (v1 is single-origin path-mounted, INV-10).
- Postgres/HA backend (the surface is designed for it; the code is not written).
- Any identity-provider behaviour: no user store, no credentials, no policy engine.
