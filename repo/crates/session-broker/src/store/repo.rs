//! ALL SQL lives here, as concrete functions — no storage trait, no
//! generics over a backend (ADR-0005). The future Postgres port (§5, "HA
//! later, unchanged surface") edits these function bodies; nothing outside
//! this module should ever see a `Connection` directly.
//!
//! **Encryption boundary (INV-5, satisfied).**
//! `custody.refresh_tok`/`custody.access_tok` are encrypted at rest with
//! XChaCha20-Poly1305 under the key `store::open` loads from the configured
//! keyfile — see [`super::crypto`]. Every call site that touches those two
//! columns goes through [`seal`]/[`open`], and no caller of this module ever
//! sees ciphertext or needs to know a key exists.

use rusqlite::{params, Connection, OptionalExtension};

use crate::clock::Timestamp;
use crate::session::{CustodyId, CustodyStatus, SessionStatus, Sid};
use crate::token::TokenHash;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("sealed value could not be opened: {0}")]
    Open(String),
    #[error("corrupt row: {0}")]
    Corrupt(String),
}

// ---------------------------------------------------------------------
// Encryption boundary (see module docs).
// ---------------------------------------------------------------------

// XChaCha20-Poly1305 under the keyfile key, which `store::open` loads. Kept as
// thin aliases here so every call site in this module reads the same as it did
// when these were placeholders — the boundary was designed for exactly this
// substitution.
pub(crate) use super::crypto::{open, seal};

// ---------------------------------------------------------------------
// Status <-> TEXT column mapping. Kept local to the SQL boundary rather
// than as trait impls on the domain types, since `session.rs` has no
// business knowing the store's string encoding.
// ---------------------------------------------------------------------

fn custody_status_to_str(status: CustodyStatus) -> &'static str {
    match status {
        CustodyStatus::Ok => "ok",
        CustodyStatus::Degraded => "degraded",
        CustodyStatus::Dead => "dead",
    }
}

fn custody_status_from_str(s: &str) -> Result<CustodyStatus, RepoError> {
    match s {
        "ok" => Ok(CustodyStatus::Ok),
        "degraded" => Ok(CustodyStatus::Degraded),
        "dead" => Ok(CustodyStatus::Dead),
        other => Err(RepoError::Corrupt(format!(
            "unknown custody status {other:?}"
        ))),
    }
}

fn session_status_to_str(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Alive => "alive",
        SessionStatus::Tombstoned => "tombstoned",
    }
}

fn session_status_from_str(s: &str) -> Result<SessionStatus, RepoError> {
    match s {
        "alive" => Ok(SessionStatus::Alive),
        "tombstoned" => Ok(SessionStatus::Tombstoned),
        other => Err(RepoError::Corrupt(format!(
            "unknown session status {other:?}"
        ))),
    }
}

fn hash_bytes_from_blob(blob: Vec<u8>) -> Result<[u8; 32], RepoError> {
    let len = blob.len();
    blob.try_into()
        .map_err(|_| RepoError::Corrupt(format!("token_hash blob has {len} bytes, expected 32")))
}

// ---------------------------------------------------------------------
// custody
// ---------------------------------------------------------------------

/// A custody row with its two encrypted-at-rest columns already opaque to
/// callers: `refresh_tok`/`access_tok` here are plaintext (already through
/// [`open`] on the way in), and [`insert_custody`]/[`update_custody_success`]
/// seal them on the way out. No caller of this module ever touches
/// ciphertext directly.
#[derive(Debug, Clone)]
pub struct CustodyRow {
    pub custody_id: CustodyId,
    pub sub: String,
    pub refresh_tok: Vec<u8>,
    pub access_tok: Vec<u8>,
    pub access_exp: Timestamp,
    pub scope: Option<String>,
    pub status: CustodyStatus,
    pub next_refresh: Timestamp,
    pub fail_count: i64,
    pub updated_at: Timestamp,
}

pub fn insert_custody(conn: &Connection, row: &CustodyRow) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO custody
            (custody_id, sub, refresh_tok, access_tok, access_exp, scope, status, next_refresh, fail_count, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.custody_id.0,
            row.sub,
            seal(&row.refresh_tok),
            seal(&row.access_tok),
            row.access_exp.secs(),
            row.scope,
            custody_status_to_str(row.status),
            row.next_refresh.secs(),
            row.fail_count,
            row.updated_at.secs(),
        ],
    )?;
    Ok(())
}

pub fn load_custody(
    conn: &Connection,
    custody_id: &CustodyId,
) -> Result<Option<CustodyRow>, RepoError> {
    let raw = conn
        .query_row(
            "SELECT custody_id, sub, refresh_tok, access_tok, access_exp, scope, status, next_refresh, fail_count, updated_at
             FROM custody WHERE custody_id = ?1",
            params![custody_id.0],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;

    let Some((
        custody_id,
        sub,
        refresh_tok,
        access_tok,
        access_exp,
        scope,
        status,
        next_refresh,
        fail_count,
        updated_at,
    )) = raw
    else {
        return Ok(None);
    };

    Ok(Some(CustodyRow {
        custody_id: CustodyId(custody_id),
        sub,
        refresh_tok: open(&refresh_tok).map_err(RepoError::Open)?,
        access_tok: open(&access_tok).map_err(RepoError::Open)?,
        access_exp: Timestamp(access_exp),
        scope,
        status: custody_status_from_str(&status)?,
        next_refresh: Timestamp(next_refresh),
        fail_count,
        updated_at: Timestamp(updated_at),
    }))
}

// ---------------------------------------------------------------------
// api_key (v2) — backend credentials for the internal token lane
// ---------------------------------------------------------------------

/// An API key as an admin console sees it. Note what is absent: the secret.
/// It exists in plaintext exactly once, in the response to the create call,
/// and is never recoverable afterwards — so a compromised console database
/// leaks *who has access*, not access itself.
#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub key_id: String,
    pub name: String,
    pub created_at: Timestamp,
    pub created_by: Option<String>,
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

pub fn insert_api_key(
    conn: &Connection,
    key_id: &str,
    name: &str,
    key_hash: &[u8],
    created_by: Option<&str>,
    now: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO api_key (key_id, name, key_hash, created_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![key_id, name, key_hash, now.secs(), created_by],
    )?;
    Ok(())
}

/// Every key, live and revoked, newest first.
///
/// Revoked keys are kept rather than deleted: "this key was revoked last
/// Tuesday" is the answer an incident review needs, and a row that vanishes
/// cannot give it.
pub fn list_api_keys(conn: &Connection) -> Result<Vec<ApiKeyRow>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT key_id, name, created_at, created_by, last_used_at, revoked_at
         FROM api_key ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ApiKeyRow {
            key_id: r.get(0)?,
            name: r.get(1)?,
            created_at: Timestamp(r.get(2)?),
            created_by: r.get(3)?,
            last_used_at: r.get::<_, Option<i64>>(4)?.map(Timestamp),
            revoked_at: r.get::<_, Option<i64>>(5)?.map(Timestamp),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(RepoError::from)
}

/// Resolve a presented secret's hash to a LIVE key.
///
/// The `revoked_at IS NULL` predicate is the revocation itself: a revoked key
/// stops working on the next request, with no cache to wait out and no restart
/// required. That is the property that makes the console's revoke button
/// meaningful rather than advisory.
pub fn find_live_api_key(
    conn: &Connection,
    key_hash: &[u8],
) -> Result<Option<ApiKeyRow>, RepoError> {
    let row = conn
        .query_row(
            "SELECT key_id, name, created_at, created_by, last_used_at, revoked_at
             FROM api_key WHERE key_hash = ?1 AND revoked_at IS NULL",
            params![key_hash],
            |r| {
                Ok(ApiKeyRow {
                    key_id: r.get(0)?,
                    name: r.get(1)?,
                    created_at: Timestamp(r.get(2)?),
                    created_by: r.get(3)?,
                    last_used_at: r.get::<_, Option<i64>>(4)?.map(Timestamp),
                    revoked_at: r.get::<_, Option<i64>>(5)?.map(Timestamp),
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Returns false if the key was unknown or already revoked, so the caller can
/// answer 404 rather than reporting success for a no-op.
pub fn revoke_api_key(conn: &Connection, key_id: &str, now: Timestamp) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "UPDATE api_key SET revoked_at = ?1 WHERE key_id = ?2 AND revoked_at IS NULL",
        params![now.secs(), key_id],
    )?;
    Ok(changed > 0)
}

pub fn touch_api_key(conn: &Connection, key_id: &str, now: Timestamp) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE api_key SET last_used_at = ?1 WHERE key_id = ?2",
        params![now.secs(), key_id],
    )?;
    Ok(())
}

/// One custody's scheduling state, without its secrets.
///
/// The boot-time schedule rebuild needs `next_refresh` and `access_exp` and
/// nothing else, so this deliberately does not decrypt the token columns —
/// there is no reason to bring every stored refresh token into memory just to
/// populate a heap.
#[derive(Debug, Clone)]
pub struct CustodySchedule {
    pub custody_id: CustodyId,
    pub access_exp: Timestamp,
    pub next_refresh: Timestamp,
    pub status: CustodyStatus,
    pub fail_count: i64,
}

/// Every custody the keepalive worker should still be tracking (§5, "restart
/// story"). `dead` rows are excluded: their grant will never work again, so
/// scheduling them would only produce a permanent failure per tick.
pub fn live_custody_schedules(conn: &Connection) -> Result<Vec<CustodySchedule>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT custody_id, access_exp, next_refresh, status, fail_count
         FROM custody WHERE status != 'dead' ORDER BY next_refresh",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (custody_id, access_exp, next_refresh, status, fail_count) = row?;
        out.push(CustodySchedule {
            custody_id: CustodyId(custody_id),
            access_exp: Timestamp(access_exp),
            next_refresh: Timestamp(next_refresh),
            status: custody_status_from_str(&status)?,
            fail_count,
        });
    }
    Ok(out)
}

/// The keepalive worker's success path (§6): both tokens rotate together
/// (the IdP may or may not rotate the refresh token; either way this writes
/// whatever the caller currently holds), status resets to `ok`, and
/// `fail_count` resets to zero.
pub fn update_custody_success(
    conn: &Connection,
    custody_id: &CustodyId,
    refresh_tok: &[u8],
    access_tok: &[u8],
    access_exp: Timestamp,
    next_refresh: Timestamp,
    now: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE custody
         SET refresh_tok = ?1, access_tok = ?2, access_exp = ?3, next_refresh = ?4,
             status = 'ok', fail_count = 0, updated_at = ?5
         WHERE custody_id = ?6",
        params![
            seal(refresh_tok),
            seal(access_tok),
            access_exp.secs(),
            next_refresh.secs(),
            now.secs(),
            custody_id.0,
        ],
    )?;
    Ok(())
}

/// The keepalive worker's transient/permanent failure path (§6): status and
/// backoff schedule move, tokens do not.
pub fn update_custody_failure(
    conn: &Connection,
    custody_id: &CustodyId,
    status: CustodyStatus,
    fail_count: i64,
    next_refresh: Timestamp,
    now: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE custody SET status = ?1, fail_count = ?2, next_refresh = ?3, updated_at = ?4
         WHERE custody_id = ?5",
        params![
            custody_status_to_str(status),
            fail_count,
            next_refresh.secs(),
            now.secs(),
            custody_id.0,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------
// session
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub sid: Sid,
    pub custody_id: CustodyId,
    pub sub: String,
    pub current_gen: u32,
    pub idle_exp: Timestamp,
    pub absolute_exp: Timestamp,
    pub status: SessionStatus,
    pub created_at: Timestamp,
    pub meta: Option<String>,
}

pub fn insert_session(conn: &Connection, row: &SessionRow) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO session
            (sid, custody_id, sub, current_gen, idle_exp, absolute_exp, status, created_at, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            row.sid.0,
            row.custody_id.0,
            row.sub,
            row.current_gen,
            row.idle_exp.secs(),
            row.absolute_exp.secs(),
            session_status_to_str(row.status),
            row.created_at.secs(),
            row.meta,
        ],
    )?;
    Ok(())
}

/// The two session columns that move after creation: the generation counter
/// and the sliding idle expiry.
///
/// Separate from [`insert_session`] rather than folded into an upsert, because
/// the columns this deliberately does NOT touch are the point —
/// `absolute_exp`, `created_at` and `custody_id` are set once at login and any
/// write that could move them is a write that could quietly extend a session
/// past its hard ceiling.
pub fn update_session_progress(
    conn: &Connection,
    sid: &Sid,
    current_gen: u32,
    idle_exp: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE session SET current_gen = ?1, idle_exp = ?2 WHERE sid = ?3",
        params![current_gen, idle_exp.secs(), sid.0],
    )?;
    Ok(())
}

/// INV-7: the one write that ends a session. Generations are not touched —
/// every code path that resolves a generation must check the parent
/// session's status first, so an untouched `generation` row backed by a
/// tombstoned session is already inert.
pub fn tombstone_session(conn: &Connection, sid: &Sid) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE session SET status = 'tombstoned' WHERE sid = ?1",
        params![sid.0],
    )?;
    Ok(())
}

pub fn load_session(conn: &Connection, sid: &Sid) -> Result<Option<SessionRow>, RepoError> {
    let raw = conn
        .query_row(
            "SELECT sid, custody_id, sub, current_gen, idle_exp, absolute_exp, status, created_at, meta
             FROM session WHERE sid = ?1",
            params![sid.0],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()?;

    let Some((sid, custody_id, sub, current_gen, idle_exp, absolute_exp, status, created_at, meta)) =
        raw
    else {
        return Ok(None);
    };

    Ok(Some(SessionRow {
        sid: Sid(sid),
        custody_id: CustodyId(custody_id),
        sub,
        current_gen: current_gen as u32,
        idle_exp: Timestamp(idle_exp),
        absolute_exp: Timestamp(absolute_exp),
        status: session_status_from_str(&status)?,
        created_at: Timestamp(created_at),
        meta,
    }))
}

// ---------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------

/// A generation row as read back. `token_hash` is raw bytes rather than
/// [`TokenHash`] because `TokenHash` exposes no public byte constructor
/// (`token.rs` is off-limits for this milestone, and deliberately so — the
/// plaintext token, not its hash, is the thing that must never be
/// reconstructable from the store). Callers that need a `TokenHash` to
/// compare against already have one in hand from the request path.
#[derive(Debug, Clone)]
pub struct GenerationRow {
    pub token_hash: [u8; 32],
    pub sid: Sid,
    pub gen_no: u32,
    pub created_at: Timestamp,
    pub active_until: Timestamp,
    pub superseded_at: Option<Timestamp>,
}

pub fn insert_generation(
    conn: &Connection,
    sid: &Sid,
    gen_no: u32,
    hash: &TokenHash,
    created_at: Timestamp,
    active_until: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO generation (token_hash, sid, gen_no, created_at, active_until, superseded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
        params![
            hash.as_bytes().as_slice(),
            sid.0,
            gen_no,
            created_at.secs(),
            active_until.secs(),
        ],
    )?;
    Ok(())
}

/// Mark a generation superseded (mint of its successor). Not in the task's
/// literal "insert/delete" pair, but required for the schema's
/// `superseded_at` column to mean anything durably — without it, a restart
/// would forget which generation was mid-grace and rehydrate every
/// generation as if freshly minted. `session.rs`'s `mint()` sets this field
/// on the previous current generation every time it rotates.
pub fn update_generation_superseded(
    conn: &Connection,
    hash: &TokenHash,
    superseded_at: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE generation SET superseded_at = ?1 WHERE token_hash = ?2",
        params![superseded_at.secs(), hash.as_bytes().as_slice()],
    )?;
    Ok(())
}

pub fn delete_generation(conn: &Connection, hash: &TokenHash) -> Result<(), RepoError> {
    conn.execute(
        "DELETE FROM generation WHERE token_hash = ?1",
        params![hash.as_bytes().as_slice()],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------
// txn (INV-3)
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TxnRow {
    pub txn_id: Vec<u8>,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub created_at: Timestamp,
}

pub fn insert_txn(conn: &Connection, row: &TxnRow) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO txn (txn_id, state, nonce, pkce_verifier, return_to, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            row.txn_id,
            row.state,
            row.nonce,
            row.pkce_verifier,
            row.return_to,
            row.created_at.secs(),
        ],
    )?;
    Ok(())
}

/// Single-use take (INV-3): the row is read and deleted inside one
/// transaction, so a second call for the same `txn_id` — replay, or a
/// racing duplicate callback request — sees `None` rather than the same txn
/// twice.
pub fn take_txn(conn: &Connection, txn_id: &[u8]) -> Result<Option<TxnRow>, RepoError> {
    let tx = conn.unchecked_transaction()?;
    let raw = tx
        .query_row(
            "SELECT txn_id, state, nonce, pkce_verifier, return_to, created_at
             FROM txn WHERE txn_id = ?1",
            params![txn_id],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;

    let Some((txn_id_out, state, nonce, pkce_verifier, return_to, created_at)) = raw else {
        return Ok(None);
    };

    tx.execute("DELETE FROM txn WHERE txn_id = ?1", params![txn_id])?;
    tx.commit()?;

    Ok(Some(TxnRow {
        txn_id: txn_id_out,
        state,
        nonce,
        pkce_verifier,
        return_to,
        created_at: Timestamp(created_at),
    }))
}

/// Reaper sweep (§3, "one reaper sweep task"): drop txns older than their
/// 10-minute TTL. `before` is the cutoff (`now - ttl`); the caller owns the
/// TTL value since it is a domain policy, not a storage concern.
pub fn delete_expired_txns(conn: &Connection, before: Timestamp) -> Result<usize, RepoError> {
    let n = conn.execute(
        "DELETE FROM txn WHERE created_at < ?1",
        params![before.secs()],
    )?;
    Ok(n)
}

// ---------------------------------------------------------------------
// audit (ADR-0015)
//
// Append-only. There is no `update_audit`, and the only DELETE is the
// retention prune below — asserted by a test rather than left to review,
// because "append-only by convention" is how a record stops being one.
// ---------------------------------------------------------------------

/// One audit row, as stored. Built through [`crate::audit::Event`], which is
/// the only place that knows the redaction rules (INV-12).
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub at: Timestamp,
    pub action: String,
    pub outcome: String,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub subject: Option<String>,
    pub sid: Option<String>,
    pub custody_id: Option<String>,
    pub key_id: Option<String>,
    pub reason: Option<String>,
    pub client_ip_prefix: Option<String>,
    pub detail: Option<String>,
}

/// A stored row plus its sequence number, which is the pagination cursor and
/// the thing a gap is visible in.
#[derive(Debug, Clone)]
pub struct StoredAuditRow {
    pub seq: i64,
    pub row: AuditRow,
}

pub fn insert_audit(conn: &Connection, row: &AuditRow) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO audit (at, action, outcome, actor_kind, actor_id, subject, sid,
                            custody_id, key_id, reason, client_ip_prefix, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            row.at.secs(),
            row.action,
            row.outcome,
            row.actor_kind,
            row.actor_id,
            row.subject,
            row.sid,
            row.custody_id,
            row.key_id,
            row.reason,
            row.client_ip_prefix,
            row.detail,
        ],
    )?;
    Ok(())
}

/// What `/admin/audit` was asked for.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
    /// Prefix match, so `action=key.` finds both `key.issued` and
    /// `key.revoked` — the way an operator actually thinks about it.
    pub action_prefix: Option<String>,
    pub subject: Option<String>,
    pub outcome: Option<String>,
    pub actor_kind: Option<String>,
    /// Descending cursor: return rows with `seq < before_seq`.
    pub before_seq: Option<i64>,
    pub limit: u32,
}

pub fn list_audit(
    conn: &Connection,
    query: &AuditQuery,
) -> Result<Vec<StoredAuditRow>, RepoError> {
    // Built as a fixed set of optional predicates with bound parameters rather
    // than string interpolation: every value here arrives from a query string.
    let mut sql = String::from(
        "SELECT seq, at, action, outcome, actor_kind, actor_id, subject, sid,
                custody_id, key_id, reason, client_ip_prefix, detail
         FROM audit WHERE 1 = 1",
    );
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(since) = query.since {
        sql.push_str(" AND at >= ?");
        binds.push(Box::new(since.secs()));
    }
    if let Some(until) = query.until {
        sql.push_str(" AND at <= ?");
        binds.push(Box::new(until.secs()));
    }
    if let Some(prefix) = &query.action_prefix {
        sql.push_str(" AND action LIKE ? ESCAPE '\\'");
        binds.push(Box::new(format!("{}%", escape_like(prefix))));
    }
    if let Some(subject) = &query.subject {
        sql.push_str(" AND subject = ?");
        binds.push(Box::new(subject.clone()));
    }
    if let Some(outcome) = &query.outcome {
        sql.push_str(" AND outcome = ?");
        binds.push(Box::new(outcome.clone()));
    }
    if let Some(actor_kind) = &query.actor_kind {
        sql.push_str(" AND actor_kind = ?");
        binds.push(Box::new(actor_kind.clone()));
    }
    if let Some(before) = query.before_seq {
        sql.push_str(" AND seq < ?");
        binds.push(Box::new(before));
    }
    sql.push_str(" ORDER BY seq DESC LIMIT ?");
    binds.push(Box::new(query.limit.clamp(1, 1000)));

    let mut stmt = conn.prepare(&sql)?;
    let params: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(params.as_slice(), |r| {
        Ok(StoredAuditRow {
            seq: r.get(0)?,
            row: AuditRow {
                at: Timestamp(r.get(1)?),
                action: r.get(2)?,
                outcome: r.get(3)?,
                actor_kind: r.get(4)?,
                actor_id: r.get(5)?,
                subject: r.get(6)?,
                sid: r.get(7)?,
                custody_id: r.get(8)?,
                key_id: r.get(9)?,
                reason: r.get(10)?,
                client_ip_prefix: r.get(11)?,
                detail: r.get(12)?,
            },
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// `LIKE` treats `%` and `_` as wildcards, so a filter of `key_` would
/// otherwise match `key.issued`. Escaped rather than rejected: the caller typed
/// a prefix, not a pattern.
fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[derive(Debug, Clone, Default)]
pub struct AuditStats {
    pub rows: i64,
    /// `None` when the table is empty, which is different from "the oldest row
    /// is from epoch 0" — a distinction the console needs to show "no history
    /// yet" rather than "history since 1970".
    pub oldest_at: Option<Timestamp>,
    pub newest_at: Option<Timestamp>,
    pub gaps: i64,
}

pub fn audit_stats(conn: &Connection) -> Result<AuditStats, RepoError> {
    let (rows, oldest, newest): (i64, Option<i64>, Option<i64>) = conn.query_row(
        "SELECT COUNT(*), MIN(at), MAX(at) FROM audit",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let gaps: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit WHERE action = 'audit.gap'",
        [],
        |r| r.get(0),
    )?;
    Ok(AuditStats {
        rows,
        oldest_at: oldest.map(Timestamp),
        newest_at: newest.map(Timestamp),
        gaps,
    })
}

/// Retention sweep. The ONLY statement in this module that removes an audit
/// row; see the section header.
pub fn prune_audit(conn: &Connection, before: Timestamp) -> Result<usize, RepoError> {
    let n = conn.execute("DELETE FROM audit WHERE at < ?1", params![before.secs()])?;
    Ok(n)
}

// ---------------------------------------------------------------------
// rehydrate (§5, "restart story")
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RehydratedSession {
    pub session: SessionRow,
    pub generations: Vec<GenerationRow>,
}

/// Boot-time load: every alive session plus every generation row still
/// attached to it. This function applies no grace or expiry policy — that
/// judgement belongs to `session.rs` — it hands back everything the schema
/// still has on file for a live session, ordered so all of one session's
/// generations are contiguous (oldest `gen_no` first), and lets the caller
/// (the future step that populates `SessionMap` from this) decide what's
/// still resource-valid.
pub fn rehydrate(conn: &Connection) -> Result<Vec<RehydratedSession>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT s.sid, s.custody_id, s.sub, s.current_gen, s.idle_exp, s.absolute_exp, s.status, s.created_at, s.meta,
                g.token_hash, g.gen_no, g.created_at, g.active_until, g.superseded_at
         FROM session s
         JOIN generation g ON g.sid = s.sid
         WHERE s.status = 'alive'
         ORDER BY s.sid, g.gen_no",
    )?;
    let mut rows = stmt.query([])?;

    let mut out: Vec<RehydratedSession> = Vec::new();
    while let Some(r) = rows.next()? {
        let sid = Sid(r.get::<_, String>(0)?);
        let custody_id = CustodyId(r.get::<_, String>(1)?);
        let sub: String = r.get(2)?;
        let current_gen: i64 = r.get(3)?;
        let idle_exp: i64 = r.get(4)?;
        let absolute_exp: i64 = r.get(5)?;
        let status: String = r.get(6)?;
        let created_at: i64 = r.get(7)?;
        let meta: Option<String> = r.get(8)?;
        let token_hash: Vec<u8> = r.get(9)?;
        let gen_no: i64 = r.get(10)?;
        let gen_created_at: i64 = r.get(11)?;
        let active_until: i64 = r.get(12)?;
        let superseded_at: Option<i64> = r.get(13)?;

        let gen = GenerationRow {
            token_hash: hash_bytes_from_blob(token_hash)?,
            sid: sid.clone(),
            gen_no: gen_no as u32,
            created_at: Timestamp(gen_created_at),
            active_until: Timestamp(active_until),
            superseded_at: superseded_at.map(Timestamp),
        };

        match out.last_mut() {
            Some(entry) if entry.session.sid == sid => entry.generations.push(gen),
            _ => out.push(RehydratedSession {
                session: SessionRow {
                    sid,
                    custody_id,
                    sub,
                    current_gen: current_gen as u32,
                    idle_exp: Timestamp(idle_exp),
                    absolute_exp: Timestamp(absolute_exp),
                    status: session_status_from_str(&status)?,
                    created_at: Timestamp(created_at),
                    meta,
                },
                generations: vec![gen],
            }),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    fn custody_row(id: &str, now: Timestamp) -> CustodyRow {
        CustodyRow {
            custody_id: CustodyId(id.to_owned()),
            sub: "alice".to_owned(),
            refresh_tok: b"refresh-plaintext".to_vec(),
            access_tok: b"access-plaintext".to_vec(),
            access_exp: now.plus_secs(3600),
            scope: Some("openid offline_access".to_owned()),
            status: CustodyStatus::Ok,
            next_refresh: now.plus_secs(1800),
            fail_count: 0,
            updated_at: now,
        }
    }

    #[test]
    fn custody_round_trips_including_status_transitions() {
        let conn = store::open_in_memory().unwrap();
        let now = Timestamp(1_700_000_000);
        let row = custody_row("cust-1", now);

        insert_custody(&conn, &row).unwrap();
        let loaded = load_custody(&conn, &row.custody_id).unwrap().unwrap();
        assert_eq!(loaded.sub, "alice");
        assert_eq!(loaded.refresh_tok, b"refresh-plaintext");
        assert_eq!(loaded.access_tok, b"access-plaintext");
        assert_eq!(loaded.status, CustodyStatus::Ok);
        assert_eq!(loaded.fail_count, 0);

        // Transient failure: status/backoff move, tokens don't.
        update_custody_failure(
            &conn,
            &row.custody_id,
            CustodyStatus::Degraded,
            3,
            now.plus_secs(60),
            now.plus_secs(60),
        )
        .unwrap();
        let degraded = load_custody(&conn, &row.custody_id).unwrap().unwrap();
        assert_eq!(degraded.status, CustodyStatus::Degraded);
        assert_eq!(degraded.fail_count, 3);
        assert_eq!(degraded.refresh_tok, b"refresh-plaintext");

        // Success: tokens rotate, status/fail_count reset.
        update_custody_success(
            &conn,
            &row.custody_id,
            b"new-refresh",
            b"new-access",
            now.plus_secs(7200),
            now.plus_secs(5400),
            now.plus_secs(120),
        )
        .unwrap();
        let refreshed = load_custody(&conn, &row.custody_id).unwrap().unwrap();
        assert_eq!(refreshed.status, CustodyStatus::Ok);
        assert_eq!(refreshed.fail_count, 0);
        assert_eq!(refreshed.refresh_tok, b"new-refresh");
        assert_eq!(refreshed.access_tok, b"new-access");

        // Permanent failure (§6 `kill`).
        update_custody_failure(
            &conn,
            &row.custody_id,
            CustodyStatus::Dead,
            8,
            now.plus_secs(9999),
            now.plus_secs(200),
        )
        .unwrap();
        let dead = load_custody(&conn, &row.custody_id).unwrap().unwrap();
        assert_eq!(dead.status, CustodyStatus::Dead);
    }

    #[test]
    fn load_custody_of_unknown_id_is_none() {
        let conn = store::open_in_memory().unwrap();
        let missing = load_custody(&conn, &CustodyId("nope".to_owned())).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn txn_can_be_taken_exactly_once() {
        let conn = store::open_in_memory().unwrap();
        let now = Timestamp(1_700_000_000);
        let row = TxnRow {
            txn_id: vec![7; 32],
            state: "state-abc".to_owned(),
            nonce: "nonce-xyz".to_owned(),
            pkce_verifier: "verifier".to_owned(),
            return_to: "/dashboard".to_owned(),
            created_at: now,
        };
        insert_txn(&conn, &row).unwrap();

        let first = take_txn(&conn, &row.txn_id).unwrap();
        assert!(first.is_some());
        assert_eq!(first.unwrap().state, "state-abc");

        let second = take_txn(&conn, &row.txn_id).unwrap();
        assert!(second.is_none(), "second take must return None");
    }

    #[test]
    fn expired_txns_are_deleted_by_ttl_sweep() {
        let conn = store::open_in_memory().unwrap();
        let old = TxnRow {
            txn_id: vec![1; 32],
            state: "s".into(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            return_to: "/".into(),
            created_at: Timestamp(1_000),
        };
        let fresh = TxnRow {
            txn_id: vec![2; 32],
            state: "s".into(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            return_to: "/".into(),
            created_at: Timestamp(10_000),
        };
        insert_txn(&conn, &old).unwrap();
        insert_txn(&conn, &fresh).unwrap();

        let deleted = delete_expired_txns(&conn, Timestamp(5_000)).unwrap();
        assert_eq!(deleted, 1);
        assert!(take_txn(&conn, &old.txn_id).unwrap().is_none());
        assert!(take_txn(&conn, &fresh.txn_id).unwrap().is_some());
    }

    #[test]
    fn rehydrate_returns_what_was_written_after_a_simulated_restart() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "session-broker-rehydrate-test-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let now = Timestamp(1_700_000_000);

        {
            let conn = store::open(&path, &path.with_extension("key")).unwrap();
            insert_custody(&conn, &custody_row("cust-1", now)).unwrap();

            let alive = SessionRow {
                sid: Sid("sid-alive".to_owned()),
                custody_id: CustodyId("cust-1".to_owned()),
                sub: "alice".to_owned(),
                current_gen: 2,
                idle_exp: now.plus_secs(604_800),
                absolute_exp: now.plus_secs(2_592_000),
                status: SessionStatus::Alive,
                created_at: now,
                meta: None,
            };
            insert_session(&conn, &alive).unwrap();

            let tombstoned = SessionRow {
                sid: Sid("sid-dead".to_owned()),
                custody_id: CustodyId("cust-1".to_owned()),
                sub: "alice".to_owned(),
                current_gen: 1,
                idle_exp: now.plus_secs(604_800),
                absolute_exp: now.plus_secs(2_592_000),
                status: SessionStatus::Tombstoned,
                created_at: now,
                meta: None,
            };
            insert_session(&conn, &tombstoned).unwrap();

            let gen1_hash = TokenHash::of("token-one");
            let gen2_hash = TokenHash::of("token-two");
            insert_generation(&conn, &alive.sid, 1, &gen1_hash, now, now.plus_secs(600)).unwrap();
            insert_generation(
                &conn,
                &alive.sid,
                2,
                &gen2_hash,
                now.plus_secs(10),
                now.plus_secs(610),
            )
            .unwrap();
            update_generation_superseded(&conn, &gen1_hash, now.plus_secs(10)).unwrap();

            let dead_hash = TokenHash::of("token-dead-session");
            insert_generation(
                &conn,
                &tombstoned.sid,
                1,
                &dead_hash,
                now,
                now.plus_secs(600),
            )
            .unwrap();
            // Connection dropped here — simulates process exit.
        }

        // Reopen: migrations must be a no-op, and the data must still be
        // there (WAL-mode on-disk durability across a real close/reopen).
        let conn = store::open(&path, &path.with_extension("key")).unwrap();
        let sessions = rehydrate(&conn).unwrap();

        assert_eq!(sessions.len(), 1, "only the alive session should rehydrate");
        let rehydrated = &sessions[0];
        assert_eq!(rehydrated.session.sid, Sid("sid-alive".to_owned()));
        assert_eq!(rehydrated.session.current_gen, 2);
        assert_eq!(rehydrated.generations.len(), 2);
        assert_eq!(rehydrated.generations[0].gen_no, 1);
        assert!(rehydrated.generations[0].superseded_at.is_some());
        assert_eq!(rehydrated.generations[1].gen_no, 2);
        assert!(rehydrated.generations[1].superseded_at.is_none());

        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// The custody columns are the reason this service exists, so the property
    /// worth pinning at the SQL boundary is that what reaches the column is
    /// not what the caller handed in. `super::crypto` tests the cipher itself;
    /// this asserts the boundary actually routes through it — the regression
    /// that would matter is someone re-aliasing `seal` to the identity
    /// function, which a round-trip test alone would happily pass.
    #[test]
    fn the_custody_columns_are_written_encrypted() {
        let conn = crate::store::open_in_memory().unwrap();
        let now = Timestamp(1_700_000_000);
        let mut row = custody_row("cust-1", now);
        row.refresh_tok = b"upstream-refresh-token".to_vec();
        insert_custody(&conn, &row).unwrap();

        let stored: Vec<u8> = conn
            .query_row(
                "SELECT refresh_tok FROM custody WHERE custody_id = 'cust-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(
            stored,
            b"upstream-refresh-token".to_vec(),
            "the refresh token must not be readable straight out of the column"
        );

        // And it still round-trips for the code that legitimately needs it.
        let loaded = load_custody(&conn, &CustodyId("cust-1".to_owned()))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.refresh_tok, b"upstream-refresh-token".to_vec());
    }
}
