# ADR-0005: Single Storage Surface — Concrete SQL Repo on SQLite, Memory-Primary Sessions, Postgres Swap Path

## Status

Accepted (2026-07-26)

## Context

Upstream refresh tokens are irreplaceable: losing custody forces an org-wide
re-login and an IdP stampede, so custody writes cannot be lossy. Session and
generation records, by contrast, sit on the sub-millisecond hot path (ADR-0003)
and must not touch disk synchronously. A later HA story is explicitly in scope
("Postgres for HA, same surface" — §5), which constrains what the embedded
store can be: whatever is chosen now has to port to Postgres without an API
change later.

This project's house precedent, set by `security/secrets-keeper`, is an
embedded KV store (redb) for zero-config on-ramp. That precedent does not
transfer here.

## Decision

**One surface: a SQL schema on embedded SQLite (WAL mode), accessed exclusively
through a single internal `store::repo` module of concrete functions — no
storage trait, no backend pluralism.** Sessions and generations are
**memory-primary**: an in-process `DashMap<TokenHash, Arc<SessionEntry>>` is
the read path; mutations go through a single writer task over an MPSC channel
that batches into SQLite transactions (≤50 ms flush). Custody rows (refresh/
access tokens) are **written through synchronously** — no batching — because
losing one is unacceptable.

The Postgres swap, when HA is needed, is a driver change plus a migration file
to the same repo function bodies, not an API or call-site change. The DashMap
demotes from primary store to a per-instance read cache with invalidate-on-
write, and coalescing becomes a compare-and-set `UPDATE ... WHERE current_gen
= ?` (a lost race costs one extra generation, not a logout — non-invalidating
rotation, ADR-0002, absorbs it).

**This overrides the prior house preference for redb** established in
`security/secrets-keeper`. The reason is specific to this project's stated HA
path: redb's B-tree keyspace does not port to Postgres — there is no
translation from an embedded KV keyspace to relational rows without a rewrite.
SQL does port: the schema, queries, and repo function signatures used against
SQLite are the same ones that run against Postgres later. Since Postgres-for-HA
is not a hypothetical but the explicitly stated destination (§5), only a
relational embedded store satisfies "zero-config now, same surface later."
redb remains the right choice where secrets-keeper used it — this is a
project-specific override, not a retraction of that decision.

## Alternatives considered

- **redb** (house precedent). Rejected here specifically because the HA
  destination is Postgres and the keyspace model doesn't carry over — see
  above. This is the one place the architecture pass overrode house
  convention, and it is recorded here rather than silently diverging.
- **Storage trait / backend pluralism** (the pattern `iam` uses for
  `SessionStore`/`RealmStore`). Rejected: with exactly one supported
  transition (SQLite now, Postgres later, same relational surface), a trait
  boundary adds indirection without a second real implementation to justify
  it. `repo` stays concrete; Postgres arrives as edits to the function bodies.
- **Redis or a separate in-memory cache service for sessions.** Rejected: an
  in-process `DashMap` is faster (no serialization, no network hop) and
  simpler to operate for a single-instance deployment, and non-invalidating
  rotation (ADR-0002) is precisely what makes an in-process, occasionally-
  lossy cache safe to treat as primary.
- **Write-behind for custody too, matching sessions.** Rejected: custody loss
  is categorically worse than session loss — it triggers org-wide re-login,
  not one grace-window race — so it gets the stronger, slower guarantee.

## Consequences

- Write-behind means a crash inside the flush window can lose the last
  idle-slide or a just-minted generation. This is safe *only* because of
  ADR-0002: the prior generation is still valid, so no user is logged out by
  the loss — the two decisions are coupled and must not be revisited
  independently.
- The synchronous custody write path is slower than the session path by
  design; this is an accepted cost for the higher-stakes data.
- The single writer task is a scaling ceiling for a single instance; the
  documented mitigation is the Postgres CAS-based swap, not tuning the SQLite
  path further.
- When Postgres HA actually happens, the work is confined to `store/repo.rs`
  and `store/writer.rs` plus keepalive lease columns (`claimed_by`,
  `lease_until`, `FOR UPDATE SKIP LOCKED`) — no HTTP contract or call-site
  changes, which is the entire point of keeping the surface concrete instead
  of trait-abstracted prematurely.
