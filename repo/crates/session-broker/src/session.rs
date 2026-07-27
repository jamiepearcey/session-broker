//! The session state machine: resolve, coalesce, rotate, reap.
//!
//! This module is pure — no HTTP, no store, no I/O, no ambient clock. Every
//! entry point takes `now` explicitly, which is what makes the whole expiry
//! surface testable without sleeping.
//!
//! The load-bearing property is **non-invalidating rotation** (INV-6): minting a
//! new generation does not kill the previous one. A superseded generation stays
//! valid for `grace` seconds, which is what removes the refresh race entirely
//! rather than coordinating around it. Two consequences fall out of that and are
//! worth stating up front, because much of the design leans on them:
//!
//! * Concurrent refreshes are *safe*, so they only need to be made *cheap* —
//!   hence coalescing rather than locking.
//! * Losing a just-minted generation in a crash cannot log anybody out, which is
//!   what licenses the memory-primary/write-behind storage design.

use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::clock::Timestamp;
use crate::store::repo::SessionRow;
use crate::store::writer::{Command, WriterHandle};
use crate::token::{SessionToken, TokenHash};

/// Tunables for the state machine. Defaults are the values argued for in
/// `docs/architecture/implementation-strategy.md` §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// How long a generation authenticates resource access for.
    pub gen_ttl_secs: u64,
    /// How long a *superseded* generation stays valid after its successor was
    /// minted. This is the width of the race window the design tolerates.
    pub grace_secs: u64,
    /// Refreshes arriving within this window of the current generation's birth
    /// re-issue that generation instead of minting another.
    pub coalesce_secs: u64,
    /// Idle expiry, slid forward on every refresh.
    pub idle_ttl_secs: u64,
    /// Hard ceiling from session creation, never extended.
    pub absolute_ttl_secs: u64,
    /// Cap on simultaneously indexed generations per session (INV-6).
    pub max_live_gens: usize,
    /// How many just-retired token hashes to remember per session, so that
    /// presenting one is reported as a retired generation rather than an unknown
    /// token (INV-6a).
    pub retired_memory: usize,
    /// What to do with sessions whose upstream grant has died.
    pub on_upstream_revoked: RevocationPolicy,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        SessionPolicy {
            gen_ttl_secs: 600,
            grace_secs: 60,
            coalesce_secs: 30,
            idle_ttl_secs: 7 * 24 * 3600,
            absolute_ttl_secs: 30 * 24 * 3600,
            max_live_gens: 4,
            retired_memory: 8,
            on_upstream_revoked: RevocationPolicy::Kill,
        }
    }
}

/// Propagation policy when the upstream refresh grant dies (ADR-0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationPolicy {
    /// Upstream revocation is an administrative security action: kill the
    /// sessions that depend on it. The default.
    Kill,
    /// Keep broker-local sessions alive and surface `custody: "dead"`, for
    /// deployments where upstream calls are incidental.
    Degrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Sid(pub String);

/// Ordered so the keepalive scheduler can hold custodies in a binary heap.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CustodyId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Alive,
    Tombstoned,
}

/// Health of the upstream grant backing a session, surfaced to the client
/// through the meta cookie so a UI can explain itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustodyStatus {
    Ok,
    Degraded,
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    pub gen_no: u32,
    pub token_hash: TokenHash,
    pub created_at: Timestamp,
    pub active_until: Timestamp,
    pub superseded_at: Option<Timestamp>,
}

impl Generation {
    /// When this generation stops authenticating resource access. For the
    /// current generation that is its own TTL; for a superseded one it is
    /// whichever of TTL and grace runs out first.
    fn resource_valid_until(&self, grace_secs: u64) -> Timestamp {
        match self.superseded_at {
            None => self.active_until,
            Some(at) => self.active_until.min(at.plus_secs(grace_secs)),
        }
    }
}

/// Why a token no longer authenticates anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiredReason {
    Idle,
    Absolute,
    LoggedOut,
    UpstreamRevoked,
}

/// What a presented token means right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Not a token this broker issued, or one it has entirely forgotten.
    Unknown,
    /// Authenticates resource access. `newest` distinguishes the current
    /// generation from one still inside its grace window — the latter is the
    /// signal INV-6a records.
    Active { sid: Sid, gen_no: u32, newest: bool },
    /// Past its own TTL but the session is alive: refresh will succeed. This is
    /// the state a tab wakes up into.
    StaleRefreshable { sid: Sid, gen_no: u32 },
    /// A superseded generation presented after its grace window closed. Denied,
    /// and worth an anomaly event (INV-6a).
    Retired { sid: Sid, gen_no: u32 },
    /// The session itself is finished.
    HardExpired { sid: Sid, reason: ExpiredReason },
}

impl Resolution {
    /// Whether resource endpoints (`/proxy`, `/internal/token`) should serve
    /// this token.
    pub fn authenticates(&self) -> bool {
        matches!(self, Resolution::Active { .. })
    }
}

/// Why a refresh was refused. Success is deliberately total for `Active` and
/// `StaleRefreshable`: those states never fail to refresh.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefreshDenied {
    #[error("unknown session token")]
    Unknown,
    #[error("retired generation {gen_no} presented")]
    Retired { sid: Sid, gen_no: u32 },
    #[error("session expired: {reason:?}")]
    Expired { sid: Sid, reason: ExpiredReason },
}

/// The non-secret client hint carried in `broker_meta`, and returned as the body
/// of a successful refresh so the client need not parse a cookie.
///
/// INV-9: the server never reads this back. It is unsigned on purpose — signing
/// it would imply it could be trusted as input, which it must not be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub v: u8,
    pub sub: String,
    pub sid: String,
    pub gen: u32,
    pub active_until: i64,
    pub refresh_until: i64,
    pub absolute_until: i64,
    pub custody: CustodyStatus,
}

/// One session read back from durable storage at boot, ready to re-enter the
/// map. See [`SessionMap::rehydrate_session`].
#[derive(Debug)]
pub struct RestoredSession {
    pub sid: Sid,
    pub custody: CustodyId,
    pub sub: String,
    pub current_gen: u32,
    pub idle_exp: Timestamp,
    pub absolute_exp: Timestamp,
    pub gens: Vec<Generation>,
}

/// Why a session was killed. Carried on [`SessionEvent::SessionKilled`] so a
/// client can tell "you logged out" from "an administrator revoked you".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillReason {
    LoggedOut,
    UpstreamRevoked,
    AdminRevoked,
}

/// Something a live client would want to know promptly rather than at its next
/// lazy check.
///
/// These are *hints* in exactly the sense INV-9 means: they let a client react
/// within a second instead of a minute, but the enforcement is still the plain
/// 401 on the next request. A client that never receives an event is never
/// wrong, only late.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SessionEvent {
    SessionKilled { sid: Sid, reason: KillReason },
    CustodyChanged { sid: Sid, custody: CustodyStatus },
}

impl SessionEvent {
    /// The SSE `event:` name for this variant.
    pub fn name(&self) -> &'static str {
        match self {
            SessionEvent::SessionKilled { .. } => "session.killed",
            SessionEvent::CustodyChanged { .. } => "custody.changed",
        }
    }

    pub fn sid(&self) -> &Sid {
        match self {
            SessionEvent::SessionKilled { sid, .. } => sid,
            SessionEvent::CustodyChanged { sid, .. } => sid,
        }
    }
}

/// Sink for [`SessionEvent`]s. Implemented in the HTTP layer over a broadcast
/// channel; kept as a trait here so this module stays free of the runtime and
/// so tests can assert on what was announced.
pub trait SessionObserver: Send + Sync + 'static {
    fn on_event(&self, event: SessionEvent);
}

/// The material a successful login or refresh hands back to the HTTP layer.
#[derive(Debug)]
pub struct IssuedCookies {
    pub token: SessionToken,
    pub meta: SessionMeta,
    /// False when the refresh coalesced onto the existing generation. The demo
    /// app asserts on this to show that N concurrent refreshes mint once.
    pub rotated: bool,
}

/// Index maintenance a mutation implies, applied by [`SessionMap`] after the
/// entry lock is released.
///
/// Also the durability record: these are exactly the generation-table changes
/// a mutation implies, so [`SessionMap::apply`] can enqueue them in the same
/// place it fixes up the in-memory index. Deriving the writes from the same
/// value that drives the index is what keeps the two from diverging.
#[derive(Debug, Default)]
struct IndexEffects {
    added: Option<Generation>,
    /// The generation this mint superseded, if any.
    superseded: Option<(TokenHash, Timestamp)>,
    purged: Vec<TokenHash>,
}

#[derive(Debug)]
struct SessionEntry {
    sid: Sid,
    custody: CustodyId,
    sub: String,
    /// Oldest first. Every entry here is indexed and may be presented.
    gens: SmallVec<[Generation; 4]>,
    current_gen: u32,
    /// Plaintext of the *current* generation, memory-only (see `token.rs`).
    /// `None` after a restart, which downgrades coalescing to minting.
    current_token: Option<SessionToken>,
    idle_exp: Timestamp,
    absolute_exp: Timestamp,
    status: SessionStatus,
    tombstoned_at: Option<Timestamp>,
    custody_status: CustodyStatus,
    /// Recently retired hashes, newest last, bounded by `retired_memory`.
    retired: VecDeque<(TokenHash, u32)>,
}

impl SessionEntry {
    fn current(&self) -> &Generation {
        self.gens
            .last()
            .expect("a session always retains at least its current generation")
    }

    /// Session-level verdict, independent of which generation was presented.
    fn session_expiry(&self, now: Timestamp, policy: &SessionPolicy) -> Option<ExpiredReason> {
        if self.status == SessionStatus::Tombstoned {
            return Some(ExpiredReason::LoggedOut);
        }
        if now >= self.absolute_exp {
            return Some(ExpiredReason::Absolute);
        }
        if now >= self.idle_exp {
            return Some(ExpiredReason::Idle);
        }
        if self.custody_status == CustodyStatus::Dead
            && policy.on_upstream_revoked == RevocationPolicy::Kill
        {
            return Some(ExpiredReason::UpstreamRevoked);
        }
        None
    }

    fn classify(&self, hash: &TokenHash, now: Timestamp, policy: &SessionPolicy) -> Resolution {
        if let Some(reason) = self.session_expiry(now, policy) {
            return Resolution::HardExpired {
                sid: self.sid.clone(),
                reason,
            };
        }

        if let Some(gen) = self.gens.iter().find(|g| &g.token_hash == hash) {
            let newest = gen.gen_no == self.current_gen;
            return if now < gen.resource_valid_until(policy.grace_secs) {
                Resolution::Active {
                    sid: self.sid.clone(),
                    gen_no: gen.gen_no,
                    newest,
                }
            } else if newest {
                // The current generation aged out. The session is fine — this is
                // exactly the state a tab wakes up into, and refresh fixes it.
                Resolution::StaleRefreshable {
                    sid: self.sid.clone(),
                    gen_no: gen.gen_no,
                }
            } else {
                // A superseded generation presented after its grace window.
                // Denied even though it is still physically indexed: reaping is
                // an optimisation, not the semantic.
                Resolution::Retired {
                    sid: self.sid.clone(),
                    gen_no: gen.gen_no,
                }
            };
        }

        match self.retired.iter().find(|(h, _)| h == hash) {
            Some((_, gen_no)) => Resolution::Retired {
                sid: self.sid.clone(),
                gen_no: *gen_no,
            },
            None => Resolution::Unknown,
        }
    }

    fn meta(&self) -> SessionMeta {
        SessionMeta {
            v: 1,
            sub: self.sub.clone(),
            sid: self.sid.0.clone(),
            gen: self.current_gen,
            active_until: self.current().active_until.secs(),
            refresh_until: self.idle_exp.secs(),
            absolute_until: self.absolute_exp.secs(),
            custody: self.custody_status,
        }
    }

    /// Slide idle expiry, never past the absolute ceiling.
    fn slide(&mut self, now: Timestamp, policy: &SessionPolicy) {
        self.idle_exp = now.plus_secs(policy.idle_ttl_secs).min(self.absolute_exp);
    }

    fn mint(&mut self, now: Timestamp, policy: &SessionPolicy) -> (SessionToken, IndexEffects) {
        let token = SessionToken::generate();
        let hash = token.hash();

        let mut superseded = None;
        if let Some(cur) = self.gens.last_mut() {
            cur.superseded_at = Some(now);
            superseded = Some((cur.token_hash, now));
        }
        self.current_gen += 1;
        let gen = Generation {
            gen_no: self.current_gen,
            token_hash: hash,
            created_at: now,
            active_until: now.plus_secs(policy.gen_ttl_secs),
            superseded_at: None,
        };
        self.gens.push(gen);
        self.current_token = Some(token.clone());

        let mut effects = self.reap_generations(now, policy);
        effects.added = Some(gen);
        effects.superseded = superseded;
        (token, effects)
    }

    /// Drop generations that can no longer authenticate anything, then enforce
    /// the hard cap. Never touches the current generation: it is the refresh
    /// credential right up until the session itself expires.
    fn reap_generations(&mut self, now: Timestamp, policy: &SessionPolicy) -> IndexEffects {
        let mut effects = IndexEffects::default();
        let current = self.current_gen;
        let grace = policy.grace_secs;

        let mut kept: SmallVec<[Generation; 4]> = SmallVec::new();
        for gen in std::mem::take(&mut self.gens) {
            let expired = gen.gen_no != current && now >= gen.resource_valid_until(grace);
            if expired {
                self.retire(gen, &mut effects, policy);
            } else {
                kept.push(gen);
            }
        }
        self.gens = kept;

        // Cap: oldest go first. `> 1` guards the current generation, which is
        // last and must survive regardless.
        while self.gens.len() > policy.max_live_gens.max(1) {
            let gen = self.gens.remove(0);
            self.retire(gen, &mut effects, policy);
        }

        effects
    }

    fn retire(&mut self, gen: Generation, effects: &mut IndexEffects, policy: &SessionPolicy) {
        self.retired.push_back((gen.token_hash, gen.gen_no));
        while self.retired.len() > policy.retired_memory {
            if let Some((hash, _)) = self.retired.pop_front() {
                effects.purged.push(hash);
            }
        }
    }

    /// Every hash this session has any claim on, for index cleanup on removal.
    fn all_hashes(&self) -> Vec<TokenHash> {
        self.gens
            .iter()
            .map(|g| g.token_hash)
            .chain(self.retired.iter().map(|(h, _)| *h))
            .collect()
    }
}

/// The hot-path session store: a token index in front of per-session entries.
///
/// Both maps are sharded, and the lock order is always index → entry, never the
/// reverse. Index guards are dropped before an entry is touched.
pub struct SessionMap {
    policy: SessionPolicy,
    /// Set once at boot, after the HTTP layer exists. Read on every kill, so a
    /// `OnceLock` keeps the hot path lock-free.
    #[allow(clippy::type_complexity)]
    observer: std::sync::OnceLock<Arc<dyn SessionObserver>>,
    sessions: DashMap<Sid, SessionEntry>,
    index: DashMap<TokenHash, Sid>,
    /// Where write-behind durability goes (§5). Absent in the pure state-machine
    /// tests, which have no store and assert on in-memory behaviour only.
    ///
    /// The map emits these itself rather than leaving them to handlers, because
    /// a mutation's durable consequence is derivable only from the internals it
    /// just changed — which generation was superseded, which hashes were reaped
    /// — and reconstructing that at each call site would mean duplicating
    /// `mint`/`reap_generations` logic in every handler, and forgetting it in
    /// the next one.
    durability: Option<WriterHandle>,
}

impl std::fmt::Debug for SessionMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because the observer is a trait object. Session contents
        // are deliberately omitted: they are token-derived material.
        f.debug_struct("SessionMap")
            .field("sessions", &self.sessions.len())
            .field("observed", &self.observer.get().is_some())
            .finish()
    }
}

impl SessionMap {
    pub fn new(policy: SessionPolicy) -> SessionMap {
        SessionMap {
            policy,
            observer: std::sync::OnceLock::new(),
            sessions: DashMap::new(),
            index: DashMap::new(),
            durability: None,
        }
    }

    /// The production constructor: same state machine, writing behind to
    /// `writer`.
    ///
    /// Durability is write-BEHIND here, and that is safe for exactly one
    /// reason — non-invalidating rotation. Losing a just-minted generation in
    /// a crash cannot log anybody out, because the cookie it replaced is still
    /// valid. The headline feature is what licenses the performance design
    /// (§5); if rotation ever became invalidating, this would have to become
    /// write-through.
    pub fn with_durability(policy: SessionPolicy, writer: WriterHandle) -> SessionMap {
        SessionMap {
            policy,
            observer: std::sync::OnceLock::new(),
            sessions: DashMap::new(),
            index: DashMap::new(),
            durability: Some(writer),
        }
    }

    pub fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Establish a session at the end of a successful OAuth callback.
    pub fn create(
        &self,
        sid: Sid,
        custody: CustodyId,
        sub: String,
        now: Timestamp,
    ) -> IssuedCookies {
        let token = SessionToken::generate();
        let hash = token.hash();
        let absolute_exp = now.plus_secs(self.policy.absolute_ttl_secs);

        let mut gens = SmallVec::new();
        gens.push(Generation {
            gen_no: 1,
            token_hash: hash,
            created_at: now,
            active_until: now.plus_secs(self.policy.gen_ttl_secs),
            superseded_at: None,
        });

        let entry = SessionEntry {
            sid: sid.clone(),
            custody: custody.clone(),
            sub: sub.clone(),
            gens,
            current_gen: 1,
            current_token: Some(token.clone()),
            idle_exp: now.plus_secs(self.policy.idle_ttl_secs).min(absolute_exp),
            absolute_exp,
            status: SessionStatus::Alive,
            tombstoned_at: None,
            custody_status: CustodyStatus::Ok,
            retired: VecDeque::new(),
        };
        let meta = entry.meta();
        let idle_exp = entry.idle_exp;

        self.sessions.insert(sid.clone(), entry);
        self.index.insert(hash, sid.clone());

        // Session before generation: `generation.sid` is a foreign key onto
        // `session`, and the writer batches these into one transaction in
        // enqueue order, so the reverse order would fail the batch.
        self.persist(Command::InsertSession(SessionRow {
            sid: sid.clone(),
            custody_id: custody,
            sub,
            current_gen: 1,
            idle_exp,
            absolute_exp,
            status: SessionStatus::Alive,
            created_at: now,
            meta: None,
        }));
        self.persist(Command::InsertGeneration {
            sid,
            gen_no: 1,
            hash,
            created_at: now,
            active_until: now.plus_secs(self.policy.gen_ttl_secs),
        });

        IssuedCookies {
            token,
            meta,
            rotated: true,
        }
    }

    /// Reinstate one session from durable rows at boot (§5, "restart story").
    ///
    /// Browser cookies survive a restart because token hashes are durable, so
    /// this is what makes a deploy invisible to logged-in users rather than a
    /// fleet-wide logout.
    ///
    /// Two things it deliberately does NOT do:
    ///
    /// * **No durability writes.** These rows came from the store; echoing them
    ///   back would be a pointless write amplification at every boot.
    /// * **No expiry judgement.** Whether a rehydrated session is still usable
    ///   is `classify`'s answer, computed from the durable `idle_exp` /
    ///   `absolute_exp` on the next request. Filtering here would duplicate
    ///   that logic in a second place.
    ///
    /// `current_token` is `None`: the plaintext of the live generation was only
    /// ever in memory (`token.rs`). The cost is that the first refresh after a
    /// restart cannot coalesce and mints instead — one extra generation, which
    /// is harmless precisely because rotation does not invalidate.
    ///
    /// Returns false if the session has no generations, which would be a
    /// session nobody can present a cookie for.
    pub fn rehydrate_session(&self, restored: RestoredSession) -> bool {
        if restored.gens.is_empty() {
            return false;
        }
        let sid = restored.sid;
        let mut ordered: SmallVec<[Generation; 4]> = SmallVec::from_vec(restored.gens);
        ordered.sort_by_key(|g| g.gen_no);

        for gen in &ordered {
            self.index.insert(gen.token_hash, sid.clone());
        }

        self.sessions.insert(
            sid.clone(),
            SessionEntry {
                sid,
                custody: restored.custody,
                sub: restored.sub,
                gens: ordered,
                current_gen: restored.current_gen,
                current_token: None,
                idle_exp: restored.idle_exp,
                absolute_exp: restored.absolute_exp,
                status: SessionStatus::Alive,
                tombstoned_at: None,
                // Corrected by the keepalive worker's first result for this
                // custody. Assuming health at boot is right: the alternative
                // would show every user a degraded badge after a deploy.
                custody_status: CustodyStatus::Ok,
                retired: VecDeque::new(),
            },
        );
        true
    }

    /// Which session a token belongs to, regardless of whether it is still
    /// valid. Logout needs this: clearing an already-expired session must still
    /// work.
    pub fn sid_for_hash(&self, hash: &TokenHash) -> Option<Sid> {
        self.index.get(hash).map(|r| r.value().clone())
    }

    fn sid_for(&self, hash: &TokenHash) -> Option<Sid> {
        self.sid_for_hash(hash)
    }

    /// Classify a presented cookie. Read-only and allocation-light: this runs on
    /// every authenticated request.
    pub fn resolve(&self, hash: &TokenHash, now: Timestamp) -> Resolution {
        let Some(sid) = self.sid_for(hash) else {
            return Resolution::Unknown;
        };
        match self.sessions.get(&sid) {
            Some(entry) => entry.classify(hash, now, &self.policy),
            None => Resolution::Unknown,
        }
    }

    pub fn meta_for(&self, hash: &TokenHash) -> Option<SessionMeta> {
        let sid = self.sid_for(hash)?;
        self.sessions.get(&sid).map(|e| e.meta())
    }

    /// Which upstream grant backs the session a token belongs to.
    ///
    /// The internal token lane needs this to find the custody row. Kept
    /// separate from [`SessionMeta`], which is the *client hint* and is
    /// deliberately non-secret — a custody id is an internal identifier and has
    /// no business travelling to a browser.
    pub fn custody_for(&self, hash: &TokenHash) -> Option<CustodyId> {
        let sid = self.sid_for(hash)?;
        self.sessions.get(&sid).map(|e| e.custody.clone())
    }

    /// The hot path. Coalesce onto the current generation when one was minted
    /// moments ago, otherwise rotate. Performs no I/O (INV-8).
    pub fn refresh(
        &self,
        hash: &TokenHash,
        now: Timestamp,
    ) -> Result<IssuedCookies, RefreshDenied> {
        let Some(sid) = self.sid_for(hash) else {
            return Err(RefreshDenied::Unknown);
        };
        let Some(mut entry) = self.sessions.get_mut(&sid) else {
            return Err(RefreshDenied::Unknown);
        };

        match entry.classify(hash, now, &self.policy) {
            Resolution::Unknown => return Err(RefreshDenied::Unknown),
            Resolution::Retired { sid, gen_no } => {
                return Err(RefreshDenied::Retired { sid, gen_no })
            }
            Resolution::HardExpired { sid, reason } => {
                return Err(RefreshDenied::Expired { sid, reason })
            }
            Resolution::Active { .. } | Resolution::StaleRefreshable { .. } => {}
        }

        let within_coalesce = now.since(entry.current().created_at) < self.policy.coalesce_secs;

        // Coalescing re-issues the current generation, which requires its
        // plaintext — held in memory for the current generation only. After a
        // restart it is gone and we mint instead: correct, just one extra
        // generation. Minting is always a safe fallback precisely because
        // rotation does not invalidate anything.
        let coalesced = within_coalesce
            .then(|| entry.current_token.clone())
            .flatten();

        let (token, rotated, effects) = match coalesced {
            Some(token) => (token, false, IndexEffects::default()),
            None => {
                let (token, effects) = entry.mint(now, &self.policy);
                (token, true, effects)
            }
        };

        entry.slide(now, &self.policy);
        let meta = entry.meta();
        let (current_gen, idle_exp) = (entry.current_gen, entry.idle_exp);
        drop(entry);

        self.apply(effects, &sid);
        // The slide happens whether or not the refresh rotated: a coalesced
        // refresh still moves idle expiry, and losing that on a crash would
        // expire a session that was in active use.
        self.persist(Command::UpdateSessionProgress {
            sid: sid.clone(),
            current_gen,
            idle_exp,
        });

        Ok(IssuedCookies {
            token,
            meta,
            rotated,
        })
    }

    /// Fix up the token index and enqueue the same changes for durability.
    ///
    /// One function for both so they cannot drift: every path that adds a
    /// generation to the index writes it, and every path that purges one
    /// deletes it.
    fn apply(&self, effects: IndexEffects, sid: &Sid) {
        if let Some(gen) = effects.added {
            self.index.insert(gen.token_hash, sid.clone());
            self.persist(Command::InsertGeneration {
                sid: sid.clone(),
                gen_no: gen.gen_no,
                hash: gen.token_hash,
                created_at: gen.created_at,
                active_until: gen.active_until,
            });
        }
        if let Some((hash, at)) = effects.superseded {
            self.persist(Command::SupersedeGeneration {
                hash,
                superseded_at: at,
            });
        }
        for hash in effects.purged {
            self.index.remove(&hash);
            self.persist(Command::DeleteGeneration(hash));
        }
    }

    fn persist(&self, cmd: Command) {
        if let Some(writer) = &self.durability {
            writer.enqueue(cmd);
        }
    }

    /// INV-7: one write kills every generation at once. The entry is kept until
    /// the reaper collects it so that late requests get a clean "logged out"
    /// rather than an ambiguous "unknown token".
    pub fn tombstone_session(&self, sid: &Sid, now: Timestamp) -> bool {
        self.tombstone_session_with_reason(sid, now, KillReason::LoggedOut)
    }

    /// As [`SessionMap::tombstone_session`], naming *why* — which is what the
    /// client is told over the event stream.
    pub fn tombstone_session_with_reason(
        &self,
        sid: &Sid,
        now: Timestamp,
        reason: KillReason,
    ) -> bool {
        let killed = match self.sessions.get_mut(sid) {
            Some(mut entry) if entry.status == SessionStatus::Alive => {
                entry.status = SessionStatus::Tombstoned;
                entry.tombstoned_at = Some(now);
                entry.current_token = None;
                true
            }
            _ => false,
        };
        if killed {
            // Logout is the one mutation whose loss would be a security
            // failure rather than an inconvenience: a tombstone lost in the
            // batch window would come back alive on the next restart. It is
            // still enqueued rather than written through — the writer flushes
            // on a ≤50 ms interval and a crash inside that window is the same
            // exposure as the request never having arrived — but it is the
            // first candidate if that judgement is ever revisited.
            self.persist(Command::TombstoneSession(sid.clone()));
            // Announced from inside the map, not from the three call sites that
            // kill sessions, so there is exactly one path that kills and one
            // that announces. A future fourth caller cannot forget.
            self.announce(SessionEvent::SessionKilled {
                sid: sid.clone(),
                reason,
            });
        }
        killed
    }

    /// Publish to the observer if one is installed. Never panics and never
    /// blocks: a full or absent event channel must not affect session state.
    fn announce(&self, event: SessionEvent) {
        if let Some(observer) = self.observer.get() {
            observer.on_event(event);
        }
    }

    /// Install the event sink. Called once at boot; later calls are ignored.
    pub fn set_observer(&self, observer: Arc<dyn SessionObserver>) {
        let _ = self.observer.set(observer);
    }

    /// Kill every session backed by a custody whose upstream grant has died.
    /// One custody may back several sessions for the same user (ADR-0011).
    pub fn tombstone_by_custody(&self, custody: &CustodyId, now: Timestamp) -> usize {
        let sids: Vec<Sid> = self
            .sessions
            .iter()
            .filter(|e| &e.custody == custody && e.status == SessionStatus::Alive)
            .map(|e| e.sid.clone())
            .collect();
        sids.iter()
            .filter(|sid| self.tombstone_session_with_reason(sid, now, KillReason::UpstreamRevoked))
            .count()
    }

    /// Record upstream health so it can surface in the meta cookie. Does not
    /// itself tombstone — the keepalive worker decides that, per policy.
    pub fn set_custody_status(&self, custody: &CustodyId, status: CustodyStatus) -> usize {
        let mut touched = 0;
        let mut changed: Vec<Sid> = Vec::new();
        for mut entry in self.sessions.iter_mut() {
            if &entry.custody == custody {
                if entry.custody_status != status {
                    changed.push(entry.sid.clone());
                }
                entry.custody_status = status;
                touched += 1;
            }
        }
        // Announced outside the iteration: the observer is arbitrary code and
        // must never run while a DashMap shard is held.
        for sid in changed {
            self.announce(SessionEvent::CustodyChanged {
                sid,
                custody: status,
            });
        }
        touched
    }

    /// Periodic collection: drop dead generations, then whole sessions that are
    /// past their usable life. Returns (sessions removed, generations retired).
    pub fn sweep(&self, now: Timestamp) -> (usize, usize) {
        let mut retired = 0;
        let mut removable: Vec<Sid> = Vec::new();

        for mut entry in self.sessions.iter_mut() {
            let collectible = match entry.session_expiry(now, &self.policy) {
                Some(ExpiredReason::LoggedOut) => entry
                    .tombstoned_at
                    .is_some_and(|at| now.since(at) >= self.policy.grace_secs),
                // A hard-expired session still answers with a precise reason
                // until its own grace has passed, then it is simply forgotten.
                Some(_) => now.since(entry.idle_exp) >= self.policy.grace_secs,
                None => false,
            };
            if collectible {
                removable.push(entry.sid.clone());
                continue;
            }
            let before = entry.gens.len();
            let sid = entry.sid.clone();
            let effects = entry.reap_generations(now, &self.policy);
            retired += before.saturating_sub(entry.gens.len());
            drop(entry);
            self.apply(effects, &sid);
        }

        let mut removed = 0;
        for sid in removable {
            if let Some((_, entry)) = self.sessions.remove(&sid) {
                for hash in entry.all_hashes() {
                    self.index.remove(&hash);
                }
                removed += 1;
            }
        }
        (removed, retired)
    }
}

#[cfg(test)]
mod tests;
