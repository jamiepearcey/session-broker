# session-broker — Architecture & Implementation Strategy

Source: architecture pass by the architect model (Fable), 2026-07-26, against the
design settled in discussion. Decisions below are treated as fixed unless an ADR
supersedes them. The seven open questions it raised are resolved at the end of
this document.

---

## 1. Strategy & positioning

`session-broker` is a self-hosted token custodian between a browser SPA and an
upstream OIDC provider. It owns exactly three hard problems and refuses
everything else:

1. **Session continuity without races.** Non-invalidating, generation-based
   cookie rotation with a grace window, so concurrent tabs/requests can never log
   each other out. This is the load-bearing feature; everything else exists to
   support it.
2. **Local-only fast refresh.** Session cookie lifetime is fully decoupled from
   upstream token lifetime. Refresh is an in-process memory operation (target p99
   < 1 ms, no network). A background worker keeps every upstream refresh-token
   grant alive independently.
3. **Upstream token custody as a product surface.** Backends, and a minimal proxy
   lane, use the always-fresh upstream access token; the browser never sees it.

**What it is not:** an IdP (no users, passwords, consent), an authorization engine
(no RBAC/policy), a general reverse proxy (the proxy lane injects a header and
forwards — nothing else), and not multi-tenant.

**The gap.** The surveyed field splits into IdPs (Ory Kratos, Keycloak, Authentik,
Zitadel, Pocket ID) and auth proxies (oauth2-proxy, Authelia, Tinyauth). The
proxies all couple cookie refresh to upstream token refresh on the request path —
oauth2-proxy specifically encrypts the refresh token *into* the cookie, refreshes
upstream synchronously mid-request, and has a documented history of
concurrent-refresh races and logout storms. None offer: (a) rotation that is
deliberately non-invalidating, (b) stateful background keepalive decoupling
session TTL from token TTL, (c) sub-millisecond local refresh. That triple is the
product. Target: ~1–2k lines of Rust, zero-config single binary, embedded store.

**Server-smart / client-dumb ethos.** Every guarantee (rotation safety, CSRF,
token freshness, logout completeness) lives server-side. The React client is ~300
lines that only needs to know *when* to act (via the meta cookie), never *how*
auth works.

---

## 2. Threat model & security invariants

Adversaries considered: network attacker on other origins (CSRF, open redirect);
XSS on the app origin (partially out of scope — `HttpOnly` limits blast radius,
but XSS can drive the proxy lane: stated residual risk); cookie thief
(malware/physical); store-file thief; malicious or compromised upstream responses.

The implementation must never violate these. Each maps to at least one test.

- **INV-1 (Cookie hardening).** Session cookie is `__Host-`-prefixed:
  `Secure; HttpOnly; Path=/; SameSite=Lax`, no `Domain`. **SameSite decision: Lax,
  everywhere.** Because (a) the OAuth callback is a cross-site top-level GET
  navigation — the transient txn cookie must survive it, and `Strict` cookies are
  stripped there; (b) `Strict` on the session cookie breaks top-level navigation
  into the proxy lane or any future SSR path while buying nothing, because (c)
  CSRF protection must not rest on SameSite anyway (INV-2). Lax + explicit origin
  checks is strictly stronger than Strict alone.
- **INV-2 (CSRF).** Every state-mutating cookie-authenticated endpoint
  (`POST /session/refresh`, `/logout`, proxy-lane non-GET) requires
  `Sec-Fetch-Site: same-origin` (or `none` for direct navigation where explicitly
  allowed), falling back to `Origin` header equality when `Sec-Fetch-*` is absent.
  Failures get `403 csrf_rejected` before any state is touched. The one exception
  — the interactive GET refresh navigation — mutates nothing except issuing a
  cookie to the legitimate cookie holder, which is not a CSRF-exploitable effect;
  session extension via forced cross-site GET is accepted residual risk (ADR-0004).
- **INV-3 (OAuth transaction integrity).** Each login attempt creates a
  server-side txn record `{state, pkce_verifier, nonce, return_to, created_at}`
  with 10-minute TTL, single-use (deleted on first callback touch, success or
  failure). The browser carries only a random txn id in `__Host-broker_txn`.
  Callback requires: txn cookie present; `state` param equals stored state; code
  exchange with the stored PKCE verifier; ID-token `iss`/`aud`/`exp`/`nonce`
  validated. Any failure → txn deleted, error page, no session created.
- **INV-4 (No open redirect).** `return_to` is accepted only as a same-origin
  absolute path (leading `/`, second char not `/` or `\`, no scheme, no `//`),
  validated at login-start, stored server-side in the txn, and re-validated at
  callback. The IdP redirect URI is a static configured value, never derived from
  request input.
- **INV-5 (Token secrecy).** Cookie values are 256-bit CSPRNG tokens; the store
  holds only `SHA-256(token)`. Upstream access/refresh tokens are encrypted at
  rest (XChaCha20-Poly1305, key from config/keyfile, generated on first boot).
  Store-file theft yields no usable session cookies and no plaintext upstream
  tokens without the key. Upstream tokens never appear in any browser-reachable
  response.
- **INV-6 (Bounded replay window).** Non-invalidating rotation must be bounded: at
  most `MAX_LIVE_GENS = 4` generations resource-valid per session; a generation
  older than the newest is valid only for `grace = 60 s` after its successor was
  minted. A stolen *current* cookie is valid until the next rotation + grace, or
  generation TTL — identical exposure to any bearer cookie. What we knowingly give
  up is *reuse-after-rotation detection*, not window size.
  - **INV-6a (Cheap recovery).** Every use of a non-newest generation is logged
    with (sid, gen, IP-prefix, UA-hash). Use of a *reaped* generation, or
    concurrent use of two generations from different IP-prefixes, emits a
    `session.anomaly` event (metric + structured log + optional webhook). Signal,
    not revocation — by design.
- **INV-7 (Logout is total and immediate).** All generation tokens resolve through
  the single session record. Logout tombstones that row in one write; every
  generation, the meta cookie, and the custody linkage die atomically. No path may
  validate a generation without checking its parent session is alive. Tombstones
  are retained for `grace` then reaped, so late requests get a clean 401.
- **INV-8 (Refresh never blocks on upstream).** `/session/refresh` performs no
  network I/O, ever. Upstream health is a local flag on the custody record. If
  custody is dead, refresh fails locally per policy — it never attempts inline
  upstream recovery.
- **INV-9 (Meta cookie is a hint, never an input).** The server never reads
  `broker_meta`. It is unsigned and non-secret; the client treats server responses
  (401s) as ground truth over it.
- **INV-10 (Single-origin deployment default).** Primary topology: broker
  path-mounted on the SPA's origin behind the reverse proxy (`/auth/*`,
  `/session/*`, `/proxy/*`). No CORS surface exists in this mode. Subdomain mode
  (`auth.example.com`) is a documented option requiring an explicit CORS allowlist
  with `credentials: true` — off by default.
- **INV-11 (Internal exchange is dually authenticated).** `/internal/token`
  requires both a static bearer key (broker↔backend trust) and a live session
  token (user context). Either alone yields nothing. The endpoint is additionally
  bindable to a separate listener/interface.

---

## 3. Session state machine

Three clocks: generation active TTL (`gen_ttl`, default 10 min), session idle
expiry (slides on refresh, default 7 d), absolute expiry (default 30 d, capped by
upstream policy) — plus custody health.

```
                    login/callback OK
  ANONYMOUS ────────────────────────────► ACTIVE ◄──────────────┐
      ▲                                     │                   │ refresh
      │ logout / reaped                     │ gen_ttl elapses   │ (rotate,
      │                                     ▼                   │  slide idle)
      ├────────────────────────────── STALE-REFRESHABLE ────────┘
      │                                     │
      │         idle/absolute expiry, or custody dead (default policy)
      │                                     ▼
      └──────────────────────────── HARD-EXPIRED ──► (reaped ⇒ ANONYMOUS)
```

| State | Definition | Resource auth (`/proxy`, `/internal/token`) | `POST /session/refresh` | `…?interactive=1` |
|---|---|---|---|---|
| **ANONYMOUS** | no/unknown/reaped token | 401 `invalid_session` | 401 `invalid_session` + `login_url` | 303 → IdP (nav) / 401 + `login_url` (fetch) |
| **ACTIVE** | gen within `gen_ttl` (incl. prior gens within grace), session alive, custody healthy | 200, token injected/returned | 200; coalesce or rotate; slide idle; `Set-Cookie` ×2 | same as non-interactive (no redirect — session is fine) |
| **STALE-REFRESHABLE** | `gen_ttl` (and grace) passed, but idle+absolute expiry not reached, custody healthy | 401 `session_stale` | 200; mint new gen; slide idle; `Set-Cookie` ×2 | same — succeeds locally, never redirects |
| **HARD-EXPIRED** | idle or absolute expiry passed, or custody dead under `kill` policy, or tombstoned | 401 `session_expired` | 401 `session_expired` + `login_url` | 303 → IdP with `prompt` untouched (SSO may make it invisible) |

`interactive` semantics, precisely: it changes behaviour **only** in
ANONYMOUS/HARD-EXPIRED, and only selects *how* the login requirement is
communicated — a `303` into the IdP flow when the request is a top-level
navigation (`GET /session/refresh?interactive=1&return_to=…`, detected via
`Sec-Fetch-Mode: navigate`), or `401 login_required` with a ready-made `login_url`
for fetches (a fetch cannot usefully follow a cross-origin redirect chain into an
IdP). In ACTIVE/STALE it is ignored — refresh succeeds locally.

### Rotation mechanics

- Session row holds `current_gen`. Each generation:
  `{gen_no, token_hash, created_at, active_until = created_at + gen_ttl, superseded_at}`.
- **Coalescing:** if `now − current_gen.created_at < coalesce = 30 s`, refresh
  re-issues the *current* generation's cookie (the server knows the token) rather
  than minting. This makes N concurrent refreshes from N tabs converge on one
  generation instead of a storm, with no locking beyond a sharded per-session
  mutex.
- **Rotation:** otherwise mint gen N+1 and set `superseded_at = now` on gen N. Gen
  N stays resource-valid until `min(active_until, superseded_at + grace)`.
- **Bounds:** `MAX_LIVE_GENS = 4` (structurally ≈ ⌈grace/coalesce⌉ + 2; hard cap
  enforced by reaping the oldest on mint). One reaper sweep task (30 s cadence)
  deletes generations past validity, sessions past expiry, tombstones past grace,
  and txns past TTL.
- The browser cookie jar is shared across tabs, so the real race window is only
  in-flight requests carrying the pre-rotation cookie — seconds. `grace = 60 s` is
  generous; configurable.

---

## 4. HTTP contract

All JSON errors share one shape:
`{ "error": "<code>", "detail": "...", "login_url": "..."? }`.
Codes: `invalid_session`, `session_stale`, `session_expired`, `login_required`,
`upstream_revoked`, `csrf_rejected`, `oauth_error`, `bad_request`, `rate_limited`.
All non-navigation endpoints send `Cache-Control: no-store`.

### Cookies

| Cookie | Attributes | Value |
|---|---|---|
| `__Host-broker_session` | `Secure; HttpOnly; Path=/; SameSite=Lax; Max-Age=<idle_ttl_secs>` | 43-char base64url of 32 random bytes |
| `broker_meta` | `Secure; Path=/; SameSite=Lax; Max-Age=<idle_ttl_secs>` (JS-readable) | base64url(JSON), below |
| `__Host-broker_txn` | `Secure; HttpOnly; Path=/; SameSite=Lax; Max-Age=600` | 32 random bytes, b64url |

Meta cookie payload (exact):

```json
{ "v": 1,
  "sub": "idp-subject",
  "sid": "8-char-hash-prefix",
  "gen": 7,
  "active_until": 1784070000,
  "refresh_until": 1784660000,
  "absolute_until": 1786600000,
  "custody": "ok" }
```

`custody` is one of `ok | degraded | dead`.

Cookie `Max-Age` note: both cookies live for the full idle window so the browser
keeps *sending* a stale-generation token — that token is the refresh credential.
Generation freshness is a server-side judgement, never a cookie-jar one.

### Endpoints

**`GET /auth/login?return_to=/path`** — creates txn (INV-3), sets
`__Host-broker_txn`, `303` → IdP authorization endpoint (`code`, PKCE S256,
`state`, `nonce`, configured scopes incl. `offline_access`). `400 bad_request` on
invalid `return_to`. Optional `prompt=login` passthrough for forced reauth.

**`GET /auth/callback?code=…&state=…`** (also handles `?error=…`) — validates per
INV-3; exchanges code; validates ID token; creates custody row + session row + gen
1; deletes txn; `Set-Cookie` ×2 (plus expired txn cookie); `303` → stored
`return_to`. Failures: `303` → configurable error page with `?error=oauth_error`,
never a session.

**`POST /session/refresh`** — the hot path. CSRF-checked (INV-2). Optional body
`{"interactive": bool}` (query-param equivalent for the GET form).
- 200: `Set-Cookie` ×2, body = the decoded meta payload (same JSON as the meta
  cookie — saves the client a cookie parse).
- 401: per the state table. Never 3xx on the POST form.

**`GET /session/refresh?interactive=1&return_to=/path`** — navigation form only
(`Sec-Fetch-Mode: navigate` required, else `403`). ACTIVE/STALE: refresh + `303` →
`return_to`. Otherwise `303` → IdP as if `/auth/login`.

**`GET /session`** — read-only introspection, no rotation, no side effects: `200`
meta payload or `401`. The client rarely needs it (the meta cookie covers it) but
it anchors tests and debugging.

**`POST /logout`** — CSRF-checked. Tombstones the session (INV-7), expires both
cookies, enqueues best-effort upstream revocation (RFC 7009). `200
{"idp_logout_url": "..."?}` — the client decides whether to navigate to
RP-initiated logout. Always 200, even for dead sessions (idempotent).

**`POST /internal/token`** — server-to-server (INV-11). Header
`Authorization: Bearer <broker_api_key>`; body
`{"session_token": "<cookie value as forwarded by the backend>"}`.
- 200: `{"access_token", "token_type": "Bearer", "expires_at", "scope", "sub"}` —
  the *current custodied* token; never triggers an upstream refresh inline (INV-8).
- 401 (bad key) / 403 (bad or expired session) / 409 `upstream_revoked` (custody dead).

**`ANY /proxy/{upstream}/{*path}`** — `upstream` must match a configured entry
`{name, base_url, allowed_methods?}`. Requires ACTIVE session + CSRF check for
non-GET. Strips cookies, injects `Authorization: Bearer <access_token>`, forwards,
streams the response. Denylist response-header passthrough (`Set-Cookie` is never
forwarded). Upstream auth failures pass through as-is with
`X-Broker-Upstream: <name>`. That is the entire proxy feature — no rewriting, no
caching.

**`GET /session/events`** — cookie-authenticated `text/event-stream`
(ADR-0013). Emits `session.killed` `{"sid","reason"}` (`logged_out` |
`upstream_revoked` | `admin_revoked`) and `custody.changed` `{"sid","custody"}`,
plus `: keepalive` comments every 20s. Same-origin checked; 401 when there is no
live session. Carries **no** session material and sets no cookies — `Set-Cookie`
is flushed once when the stream opens and trailers are not processed by
browsers, so cookies keep riding ordinary request/responses. A *hint* channel
only: the 401 on the next request is still what enforces a revocation.

**`GET /healthz`** (liveness + store check), **`GET /metrics`** (Prometheus text).

---

## 5. Storage & data model

**One surface: a SQL schema on embedded SQLite (WAL mode), accessed exclusively
through one internal `store::repo` module.** Rationale versus redb: the later HA
story ("Postgres for HA, same surface") requires the *portable* surface to be
relational — redb's B-tree keyspace does not port, SQL does. SQLite is equally
zero-config, and the repo module's queries stay conservative so the Postgres swap
is a driver change plus a migration file, not an API change. There is deliberately
**no storage trait and no backend pluralism** — `repo` is concrete functions;
Postgres later is an edit to their bodies.

**The memory/durability split.** Upstream refresh tokens are irreplaceable —
losing custody forces org-wide re-login and an IdP stampede — so custody is
written through synchronously. Session/generation records are hot-path, so they
are **memory-primary**: an in-process `DashMap<TokenHash, Arc<SessionEntry>>` is
the read path (this is what makes refresh sub-ms), and mutations go to a single
writer task over an MPSC channel that batches into SQLite transactions (≤50 ms
flush interval). A crash inside the batch window loses at most the last idle-slide
or a just-minted generation — and the prior generation is still valid.
**Non-invalidating rotation is what makes write-behind safe: losing a mint can
never log anyone out, because the old cookie still works.** The headline feature
licenses the performance design.

```sql
CREATE TABLE custody (
  custody_id   TEXT PRIMARY KEY,          -- uuid
  sub          TEXT NOT NULL,
  refresh_tok  BLOB NOT NULL,             -- XChaCha20-Poly1305
  access_tok   BLOB NOT NULL,
  access_exp   INTEGER NOT NULL,          -- epoch secs
  scope        TEXT,
  status       TEXT NOT NULL,             -- ok | degraded | dead
  next_refresh INTEGER NOT NULL,
  fail_count   INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL
);
CREATE TABLE session (
  sid          TEXT PRIMARY KEY,
  custody_id   TEXT NOT NULL REFERENCES custody(custody_id),
  sub          TEXT NOT NULL,
  current_gen  INTEGER NOT NULL,
  idle_exp     INTEGER NOT NULL,
  absolute_exp INTEGER NOT NULL,
  status       TEXT NOT NULL,             -- alive | tombstoned
  created_at   INTEGER NOT NULL,
  meta         TEXT                       -- ip-prefix/ua-hash at creation, for anomaly diffs
);
CREATE TABLE generation (
  token_hash    BLOB PRIMARY KEY,         -- sha256(cookie value)
  sid           TEXT NOT NULL REFERENCES session(sid),
  gen_no        INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,
  active_until  INTEGER NOT NULL,
  superseded_at INTEGER
);
CREATE INDEX gen_by_sid ON generation(sid, gen_no);
CREATE INDEX custody_sched ON custody(next_refresh) WHERE status != 'dead';
CREATE TABLE txn ( txn_id BLOB PRIMARY KEY, state TEXT, nonce TEXT,
  pkce_verifier TEXT, return_to TEXT, created_at INTEGER );
```

**Restart story:** boot = open DB → run migrations → load all alive sessions and
live generations into the DashMap (thousands of rows; milliseconds) → keepalive
worker rebuilds its schedule from `custody_sched`, executing any `next_refresh`
already in the past immediately under a jittered 30 s spread (anti-stampede).
Browser cookies remain valid across restarts because token hashes are durable. The
reaper resumes on its normal cadence.

**HA/multi-instance later, unchanged surface:** move to Postgres; the DashMap
demotes from primary to a per-instance read cache with short TTL and
invalidate-on-write; refresh coalescing becomes a single
`UPDATE … WHERE current_gen = ?` compare-and-set (a lost race costs one extra
harmless generation, not a logout — again the core property doing the work);
keepalive instances claim custody rows via lease columns (`claimed_by`,
`lease_until`, `FOR UPDATE SKIP LOCKED`). None of this changes the repo API or the
HTTP contract.

---

## 6. Background keepalive worker

One tokio task owning a `BinaryHeap<(next_refresh_at, custody_id)>`, fed by a
channel on custody creation, popping due items and dispatching refreshes through a
`Semaphore` (default 8 concurrent upstream calls).

- **Scheduling:** `next_refresh = issued_at + 0.6 × access_token_lifetime`, plus
  jitter `U(−10%, +10%)` of the lead margin. The 0.6 factor leaves two full retry
  budgets before real expiry.
- **Success:** store the new access token (and rotated refresh token if the IdP
  rotates them — both behaviours must be handled), reschedule, `fail_count = 0`,
  `status = ok`.
- **Transient failure** (network, 5xx, 429 honouring `Retry-After`): exponential
  backoff `min(1 s × 2^n, 5 min)` with full jitter; `status = degraded` once
  `access_exp` has actually passed (the meta cookie surfaces
  `"custody": "degraded"`; sessions stay ACTIVE — session auth does not depend on
  upstream liveness, only token exchange and the proxy lane do, and those return
  `upstream_revoked`-flavoured errors while degraded). Retries continue as long as
  the refresh token might still be honoured.
- **Permanent failure** (`invalid_grant` — refresh token revoked/expired/consumed):
  `status = dead`, stop scheduling. Propagation policy
  `on_upstream_revoked = kill | degrade`, **default `kill`**: all sessions
  referencing that custody are tombstoned (reusing the INV-7 machinery), because
  upstream revocation is an administrative security action and must propagate.
  `degrade` keeps sessions alive for broker-local auth with `custody: "dead"` in
  meta, for deployments where the broker session is the product and upstream calls
  are incidental. One custody may back several sessions (same user, multiple
  logins) — `kill` affects all of them; this is documented behaviour.
- **Refresh-token rotation hazard:** if the IdP rotates refresh tokens with
  single-use semantics, a crash between the upstream response and the durable
  write orphans the grant. Mitigation: write the new refresh token *before*
  acknowledging the schedule update (write-through; this path is off the hot path
  so INV-8 is unaffected), and never issue concurrent refreshes for one custody
  (heap-entry uniqueness per custody, enforced by a `refreshing` flag).
- **Observability:** counters `keepalive_refresh_total{outcome}`, gauge
  `custody_status{status}`, histogram `keepalive_upstream_latency`, and structured
  logs per transition. `session.anomaly` events (INV-6a) share the same event pipe.

---

## 7. Rust implementation plan

**Dependencies** — each earns its place; the total is deliberately short.

| Crate | Why |
|---|---|
| `axum` + `tokio` + `tower-http` (trace, timeout) | axum's extractor model keeps the CSRF/cookie guards composable |
| `openidconnect` | discovery, PKCE, `state`/`nonce`, ID-token signature + claims validation — the code you must not hand-write; pulls `oauth2` transitively |
| `reqwest` (rustls) | upstream calls + proxy lane; shares the TLS stack, no OpenSSL |
| `rusqlite` (bundled) | sync SQLite behind the single writer task — a dedicated writer thread + channel is simpler and faster than an async pool for a single-writer workload; `sqlx`'s compile cost and query-macro coupling buy nothing here |
| `dashmap` | hot-path session map; no need for `moka` since expiry is domain-driven, not cache-policy-driven |
| `serde`/`serde_json`, `rand`, `sha2`, `chacha20poly1305`, `base64` | contract + INV-5 primitives |
| `jiff` | time, behind a `Clock` abstraction for test control (§9) |
| `tracing` + `tracing-subscriber`, `metrics` + Prometheus exporter | observability spine |
| env + TOML config | zero-config default, one optional file |

**Module layout** (~1.6k lines estimated), under `repo/crates/session-broker/`:

```
src/
  main.rs            // wiring: config → store → state → worker → router
  config.rs
  clock.rs           // Clock trait: SystemClock / TestClock
  store/mod.rs       // schema + migrations
  store/repo.rs      // ALL SQL lives here; concrete fns, no trait
  store/writer.rs    // MPSC batch writer task
  session.rs         // SessionEntry, state machine, rotate/coalesce/reap — the crown jewels
  oauth.rs           // openidconnect client, txn lifecycle, callback validation
  keepalive.rs       // heap scheduler, backoff, propagation
  http/mod.rs        // router
  http/guards.rs     // CSRF (INV-2), cookie extraction, Sec-Fetch checks
  http/auth.rs       // /auth/login, /auth/callback
  http/session.rs    // /session, /session/refresh, /logout
  http/exchange.rs   // /internal/token
  http/proxy.rs      // proxy lane
  http/error.rs      // error taxonomy → responses
```

Key types (signatures only):

```rust
pub struct TokenHash([u8; 32]);                     // the only form the store ever sees
pub struct SessionEntry { sid: Sid, custody: CustodyId, sub: String,
    gens: SmallVec<[Generation; 4]>, current: GenNo,
    idle_exp: Timestamp, absolute_exp: Timestamp, status: SessionStatus }

pub enum Resolution { Active(GenNo), StaleRefreshable, HardExpired(ExpiredReason), Unknown }

impl SessionMap {
    pub fn resolve(&self, t: &TokenHash, now: Timestamp) -> Resolution;
    /// coalesce-or-rotate; returns cookie material + meta payload; never fails for Active/Stale
    pub fn refresh(&self, t: &TokenHash, now: Timestamp) -> Result<IssuedCookies, RefreshDenied>;
    pub fn tombstone_session(&self, sid: &Sid, now: Timestamp);
    pub fn tombstone_by_custody(&self, c: &CustodyId, now: Timestamp);
}

pub trait Clock: Send + Sync { fn now(&self) -> Timestamp; }
```

**Milestones** — each independently testable. ⚙ = mechanical (delegatable),
★ = needs care.

- **M0 ⚙** Skeleton: config, clock, store schema + migrations, writer task,
  `/healthz`, `/metrics`. Test: boot, restart, schema idempotence.
- **M1 ★** `session.rs` state machine — *pure, no HTTP, no store*:
  resolve/refresh/coalesce/grace/reap against `TestClock`. The property tests live
  here. Build it first and alone.
- **M2 ★** OAuth: login/callback against the mock IdP. Covers INV-3/INV-4 negative
  cases exhaustively.
- **M3 ⚙** HTTP session endpoints wiring M1: refresh, `/session`, logout,
  cookie/CSRF guards, meta cookie. Contract tests straight from §4's tables.
- **M4 ★** Keepalive worker + custody lifecycle + propagation policies, against the
  mock IdP with fault injection (`invalid_grant`, 5xx, rotating refresh tokens,
  crash-between-refresh-and-write).
- **M5 ⚙** `/internal/token` + proxy lane.
- **M6 ⚙** Reaper, restart rehydration test, anomaly events, metrics polish, rate
  limiting on `/auth/*`.
- **M7 ★** React SDK (§8).
- **M8 ⚙** Demo app + measured benchmarks.
- **M9 ★** Race/multi-tab test harness (§9).

> Deviation from the architecture pass: it proposed a ~100-line in-test mock IdP
> for M2. We build a fuller standalone fixture crate instead —
> `repo/crates/mock-idp` — with a `/__test__/` control surface (forced expiry,
> revocation, injected failures, and a `/token` call counter). The counter is what
> lets tests *prove* INV-8 rather than assert it by inspection.

---

## 8. React client plan

Package `@session-broker/react`, ~300 lines, three modules and one provider:

- **`meta.ts`** — parse `broker_meta` from `document.cookie` into a typed
  `SessionMeta | null`. Pure.
- **`leader.ts`** — `navigator.locks.request('broker-refresh-leader', () => new
  Promise(() => {}))`; exposes a `held` flag. Fallback where Web Locks are absent
  (pre-2022): let every tab run the timer. Server-side coalescing makes redundant
  leaders harmless — **server coalescing is the safety net for every client bug in
  this file**, which is why no fallback complexity is warranted.
- **`refresh.ts`** — single-flight in-tab promise around `POST /session/refresh`;
  the timer (leader only) fires at `active_until − skew(30 s)`;
  `visibilitychange`/`focus`/`online` handlers do a lazy check in *every* tab
  (covers background-tab throttling, and non-leader tabs waking before the cookie
  jar updates).
- **`fetch.ts`** — `brokerFetch(input, init)`: pass-through; on 401 with a
  refreshable meta state → await the single-flight refresh → retry exactly once; on
  `login_required` → surface to the app. Never auto-redirect from a fetch —
  navigation is an app decision, exposed as `login(returnTo?)` which navigates to
  `/session/refresh?interactive=1&return_to=…`.

App surface:

```tsx
<SessionProvider>                          // mounts leader election + timers once
const { status, meta, login, logout } = useSession();
// status: 'anonymous' | 'active' | 'refreshing' | 'expired'
brokerFetch(url, init)                     // or wrapFetch(customFetch)
```

### Demo app

Vite + the SDK + a one-page dashboard. It must make the invisible machinery
observable, with **real measured numbers only**:

1. Live panel: decoded meta cookie (generation number ticking up on rotation),
   session status, custody status — updating in real time.
2. Leader badge: "this tab is leader". Open three tabs, close the leader, watch
   another promote (Web Lock release) — with no coordination traffic shown,
   because there is none.
3. **Forced-race button:** fire 20 parallel authenticated requests while
   simultaneously triggering refresh from two tabs; display *0 failed requests, 1
   generation minted* (coalescing). This is the money shot for the headline
   property.
4. Refresh log: timestamped entries with measured `performance.now()` round-trip
   per refresh, plus a server-reported handler time (`X-Broker-Handler-Us`) so the
   sub-ms server claim is shown as server-side truth separately from network RTT.
5. "Kill upstream" toggle driving the mock IdP → watch custody go degraded → dead
   → session behaviour per policy, live.
6. Restart button on the broker (the demo runs it as a child process) → cookies
   survive, sessions rehydrate, timer continuity shown.

---

## 9. Test strategy

**Deterministic time.** Everything in `session.rs` and `keepalive.rs` takes
`Arc<dyn Clock>`; tests use `TestClock::advance()`. Tokio's `time::pause` covers
the worker's sleeps. No real-time sleeps anywhere in tests.

**The non-invalidating property, deterministically (M1/M3):**

- Unit: mint gen 1 → rotate → assert gen 1 is `Active` until
  `superseded_at + grace`, `Stale` after, reaped after; assert the coalescing
  window returns an identical token; assert the `MAX_LIVE_GENS` cap holds under
  pathological rotate loops.
- Property test (`proptest`): random interleavings of
  {refresh, resource-check, advance(Δ), logout}. Invariants: no token ever
  transitions dead→alive; after logout no token resolves; a token that was `Active`
  at issue remains valid for at least `min(gen_ttl, grace)`; live generations ≤ 4.
- Concurrency harness (M9): real multithreaded runtime, N = 64 tasks sharing one
  cookie-jar snapshot, all hitting `/session/refresh` and resource endpoints
  through a `tower::Service` handle simultaneously (barrier-released). Assert zero
  401s, ≤ 1 new generation per coalesce window, and that every returned cookie
  resolves.
- The oauth2-proxy failure mode as a named regression test: two concurrent
  refreshes with the *old* cookie after rotation — both must succeed.

**Keepalive:** mock IdP with scriptable responses; paused-time assertions on
schedule points, jitter bounds, backoff sequence, and `Retry-After` honouring.
Crash-recovery test: drop the worker mid-refresh after upstream success but before
the write, restart, assert no orphaned grant (write-through ordering).

**Restart:** integration test boots the broker on a temp DB, establishes sessions,
SIGKILLs the process, reboots, asserts cookies still resolve and the worker
schedule is rebuilt.

**Multi-tab client (Playwright):** Web Locks are per browser *profile* and tabs
within one context share them — so open 3 pages in one context; assert exactly one
leader (via the demo's exposed state); close the leader page and assert the next
promotes in < 1 s. Clock-skew test via CDP `Emulation.setVirtualTimePolicy` where
available, else the `visibilitychange` path: background a tab beyond `gen_ttl`,
foreground it, assert the lazy refresh fires before any app fetch 401s. The
forced-race scenario runs headless in CI with real assertions, and its measured
numbers are written to a JSON artifact the demo page renders — same numbers, never
fabricated.

---

## 10. Resolved decisions

The architecture pass raised seven open questions. All are resolved in favour of
its recommendation; each is recorded as an ADR and may be revisited with evidence.

| # | Question | Resolution |
|---|---|---|
| 1 | `on_upstream_revoked` default | **`kill`**. Upstream revocation must mean something; `degrade` is opt-in. |
| 2 | RP-initiated logout by default | **No.** Return `idp_logout_url`; never auto-navigate. SSO logout is an app-level product decision. |
| 3 | `gen_ttl` = 10 min | **Yes.** Short replay half-life at ~6 refreshes/hour/user. Also bounds proxy-lane access staleness. |
| 4 | One custody per login vs shared per `sub` | **Per login.** Simpler kill semantics, no cross-device coupling; costs one upstream grant per device, which IdPs expect. |
| 5 | Subdomain mode in v1 | **Defer.** Path-mount only (INV-10) until a real deployment needs CORS mode. |
| 6 | `/internal/token` listener | **Second bind** (localhost/internal interface), default-on. Cheap, removes a class of exposure. |
| 7 | Encrypt-at-rest key management | **Keyfile beside the DB**, env override. Keyfile + DB theft = tokens, but that is one box and one trust zone. |

Storage is the one place where the architecture pass overrode a prior house
preference (redb, per `secrets-keeper`): SQL wins here because the stated HA path
is Postgres, and only a relational surface ports. Recorded in ADR-0005.
