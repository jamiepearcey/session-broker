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
use super::crypto::{context, key_id_of, KeyRing};
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
            seal(&row.refresh_tok, &context(&row.custody_id.0, "refresh")),
            seal(&row.access_tok, &context(&row.custody_id.0, "access")),
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

/// What a [`reseal_custody`] pass found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResealReport {
    /// Rows moved from an older key to the active one.
    pub resealed: usize,
    /// Rows already under the active key.
    pub current: usize,
    /// Rows that would not open (wrong/removed key, or altered). Left untouched:
    /// rewriting what cannot be read would destroy the only copy.
    pub failed: usize,
}

/// Re-encrypt every custody row still sealed under a retired key.
///
/// Run inside the writer's transaction, so it cannot interleave with a
/// keepalive rotation: the row it reads is the row it rewrites. That matters
/// because a refresh token regressing to an older value is an unrecoverable
/// loss of the grant at an IdP that rotates them.
pub fn reseal_custody(conn: &Connection) -> Result<ResealReport, RepoError> {
    reseal_custody_with(conn, super::crypto::ring())
}

/// Every sealed column in the store, moved onto the active key: custody tokens
/// and signing-key seeds. This is what the boot `Reseal` runs.
///
/// One entry point on purpose. A table with a sealed column that the reseal
/// does not visit keeps its rows under the old key for ever, and the first
/// anyone hears of it is when that key is deleted from the keyfile.
pub fn reseal_all(conn: &Connection) -> Result<ResealAll, RepoError> {
    reseal_all_with(conn, super::crypto::ring())
}

/// What [`reseal_all`] found, per table.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResealAll {
    pub custody: ResealReport,
    pub signing_keys: ResealReport,
}

pub(crate) fn reseal_all_with(conn: &Connection, ring: &KeyRing) -> Result<ResealAll, RepoError> {
    Ok(ResealAll {
        custody: reseal_custody_with(conn, ring)?,
        signing_keys: reseal_signing_keys_with(conn, ring)?,
    })
}

pub(crate) fn reseal_custody_with(
    conn: &Connection,
    ring: &KeyRing,
) -> Result<ResealReport, RepoError> {
    let active = ring.active_id();
    let mut report = ResealReport::default();
    let mut stmt = conn.prepare("SELECT custody_id, refresh_tok, access_tok FROM custody")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    for (custody_id, refresh, access) in rows {
        if key_id_of(&refresh) == Some(active) && key_id_of(&access) == Some(active) {
            report.current += 1;
            continue;
        }
        let refresh_ctx = context(&custody_id, "refresh");
        let access_ctx = context(&custody_id, "access");
        match (
            ring.open(&refresh, &refresh_ctx),
            ring.open(&access, &access_ctx),
        ) {
            (Ok(refresh_plain), Ok(access_plain)) => {
                conn.execute(
                    "UPDATE custody SET refresh_tok = ?1, access_tok = ?2 WHERE custody_id = ?3",
                    params![
                        ring.seal(&refresh_plain, &refresh_ctx),
                        ring.seal(&access_plain, &access_ctx),
                        custody_id
                    ],
                )?;
                report.resealed += 1;
            }
            _ => report.failed += 1,
        }
    }
    Ok(report)
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

    let refresh_plain =
        open(&refresh_tok, &context(&custody_id, "refresh")).map_err(RepoError::Open)?;
    let access_plain =
        open(&access_tok, &context(&custody_id, "access")).map_err(RepoError::Open)?;
    Ok(Some(CustodyRow {
        custody_id: CustodyId(custody_id),
        sub,
        refresh_tok: refresh_plain,
        access_tok: access_plain,
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

// ---------------------------------------------------------------------
// signing_key (v5) — the token issuer's Ed25519 keys
//
// No state column. A key is pending, signing or retired by where the clock
// stands against `activate_at` / `retire_at`; `removed_at` is the only thing
// a background job ever sets.
// ---------------------------------------------------------------------

/// The AAD context binding a sealed seed to its key row.
fn signing_seed_context(kid: &str) -> Vec<u8> {
    format!("signing:{kid}:seed").into_bytes()
}

/// A freshly generated key on its way to the store. The seed is plaintext here
/// and sealed by [`insert_signing_key`]; it is wiped when this is dropped.
pub struct NewSigningKey {
    pub kid: String,
    pub public_key: [u8; 32],
    pub seed: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for NewSigningKey {
    // Never prints the seed: this type rides inside `AdminWrite`, which derives
    // `Debug` (INV-12).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// A signing key as anything outside the issuer sees it: no seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyRow {
    pub kid: String,
    pub public_key: [u8; 32],
    pub created_at: Timestamp,
    pub activate_at: Timestamp,
    pub retire_at: Option<Timestamp>,
    pub removed_at: Option<Timestamp>,
}

/// A seed out of the store: `None` if it would not open.
pub type OpenedSeed = Option<zeroize::Zeroizing<[u8; 32]>>;

fn signing_key_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(SigningKeyRow, Vec<u8>)> {
    let public: Vec<u8> = r.get(1)?;
    let public_key = <[u8; 32]>::try_from(public.as_slice()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Blob,
            format!(
                "signing_key.public_key is {} bytes; 32 required",
                public.len()
            )
            .into(),
        )
    })?;
    Ok((
        SigningKeyRow {
            kid: r.get(0)?,
            public_key,
            created_at: Timestamp(r.get(3)?),
            activate_at: Timestamp(r.get(4)?),
            retire_at: r.get::<_, Option<i64>>(5)?.map(Timestamp),
            removed_at: r.get::<_, Option<i64>>(6)?.map(Timestamp),
        },
        r.get(2)?,
    ))
}

const SIGNING_KEY_COLUMNS: &str =
    "kid, public_key, seed_sealed, created_at, activate_at, retire_at, removed_at";

/// Newest first. `rowid` breaks a tie between two keys with the same second on
/// both clocks, which an immediate rotation right after boot produces.
const SIGNING_KEY_ORDER: &str = "ORDER BY activate_at DESC, created_at DESC, rowid DESC";

pub fn insert_signing_key(
    conn: &Connection,
    key: &NewSigningKey,
    now: Timestamp,
    activate_at: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO signing_key (kid, public_key, seed_sealed, created_at, activate_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key.kid,
            key.public_key.as_slice(),
            seal(key.seed.as_slice(), &signing_seed_context(&key.kid)),
            now.secs(),
            activate_at.secs(),
        ],
    )?;
    Ok(())
}

/// Add `key` and give every key before it an end date no later than
/// `retire_at`.
///
/// The predicate has two halves and both matter. `retire_at IS NULL` dates the
/// keys nothing has superseded yet. `retire_at > ?1` pulls an EARLIER date onto
/// a key that already had a later one — which is what an immediate rotation
/// needs: a key that a previous, leisurely rotation left published for another
/// day must stop being published now. A key already dated at or before
/// `retire_at` keeps its date, so rotating can shorten how long an old key
/// stays published and can never extend it. After this exactly one key — the
/// new one — is open-ended.
pub fn rotate_signing_key(
    conn: &Connection,
    key: &NewSigningKey,
    now: Timestamp,
    activate_at: Timestamp,
    retire_at: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE signing_key SET retire_at = ?1
         WHERE removed_at IS NULL AND (retire_at IS NULL OR retire_at > ?1)",
        params![retire_at.secs()],
    )?;
    insert_signing_key(conn, key, now, activate_at)
}

/// Every key ever created, removed ones included, newest first.
pub fn list_signing_keys(conn: &Connection) -> Result<Vec<SigningKeyRow>, RepoError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SIGNING_KEY_COLUMNS} FROM signing_key {SIGNING_KEY_ORDER}"
    ))?;
    let rows = stmt.query_map([], |r| signing_key_row(r).map(|(row, _)| row))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(RepoError::from)
}

/// The keys the issuer holds in memory: everything not yet removed, newest
/// first, each with its seed opened.
///
/// A seed that will not open is returned as `None` rather than failing the
/// load. Its public half is still worth publishing — tokens it signed before
/// the keyfile was lost go on verifying — and one unreadable row must not take
/// the readable ones down with it.
pub fn load_signing_keys(conn: &Connection) -> Result<Vec<(SigningKeyRow, OpenedSeed)>, RepoError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SIGNING_KEY_COLUMNS} FROM signing_key WHERE removed_at IS NULL {SIGNING_KEY_ORDER}"
    ))?;
    let rows = stmt
        .query_map([], signing_key_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .map(|(row, sealed)| {
            let seed = open(&sealed, &signing_seed_context(&row.kid))
                .ok()
                .and_then(|mut plain| {
                    let seed = <[u8; 32]>::try_from(plain.as_slice()).ok();
                    zeroize::Zeroize::zeroize(&mut plain);
                    seed.map(zeroize::Zeroizing::new)
                });
            (row, seed)
        })
        .collect())
}

/// Keys past their `retire_at` that the prune has not removed yet.
pub fn retired_signing_keys_due(
    conn: &Connection,
    now: Timestamp,
) -> Result<Vec<String>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT kid FROM signing_key
         WHERE removed_at IS NULL AND retire_at IS NOT NULL AND retire_at <= ?1",
    )?;
    let rows = stmt.query_map(params![now.secs()], |r| r.get(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(RepoError::from)
}

/// Mark one retired key removed. Returns false if it was not there, was already
/// removed, or is not past `retire_at` — the predicate is repeated here rather
/// than trusted from the caller's earlier read, because removing a key that is
/// still published breaks every verifier holding a token it signed.
pub fn remove_retired_signing_key(
    conn: &Connection,
    kid: &str,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "UPDATE signing_key SET removed_at = ?1
         WHERE kid = ?2 AND removed_at IS NULL AND retire_at IS NOT NULL AND retire_at <= ?1",
        params![now.secs(), kid],
    )?;
    Ok(changed > 0)
}

/// The signing-key half of [`reseal_all`]. Removed keys are resealed too: their
/// rows are kept, so their seeds must not be what pins an old custody key.
pub(crate) fn reseal_signing_keys_with(
    conn: &Connection,
    ring: &KeyRing,
) -> Result<ResealReport, RepoError> {
    let active = ring.active_id();
    let mut report = ResealReport::default();
    let mut stmt = conn.prepare("SELECT kid, seed_sealed FROM signing_key")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    for (kid, sealed) in rows {
        if key_id_of(&sealed) == Some(active) {
            report.current += 1;
            continue;
        }
        let ctx = signing_seed_context(&kid);
        match ring.open(&sealed, &ctx) {
            Ok(mut seed) => {
                conn.execute(
                    "UPDATE signing_key SET seed_sealed = ?1 WHERE kid = ?2",
                    params![ring.seal(&seed, &ctx), kid],
                )?;
                zeroize::Zeroize::zeroize(&mut seed);
                report.resealed += 1;
            }
            Err(_) => report.failed += 1,
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------
// tenant / principal / principal_secret / user_grant (v5) — the token
// issuer's identities, as data
//
// Nothing here is reachable from `/internal/token` or `/authz`: a principal is
// never an `api_key`. Every mutation returns whether it changed a row, so the
// admin lane can answer 404/409 and the audit row can say the same thing.
// ---------------------------------------------------------------------

/// A tenant as the admin lane sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRow {
    pub tenant_id: String,
    pub display_name: Option<String>,
    pub created_at: Timestamp,
    pub disabled_at: Option<Timestamp>,
}

pub fn list_tenants(conn: &Connection) -> Result<Vec<TenantRow>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT tenant_id, display_name, created_at, disabled_at
         FROM tenant ORDER BY tenant_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TenantRow {
            tenant_id: r.get(0)?,
            display_name: r.get(1)?,
            created_at: Timestamp(r.get(2)?),
            disabled_at: r.get::<_, Option<i64>>(3)?.map(Timestamp),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(RepoError::from)
}

/// False if the tenant already exists, disabled or not.
pub fn insert_tenant(
    conn: &Connection,
    tenant_id: &str,
    display_name: Option<&str>,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "INSERT OR IGNORE INTO tenant (tenant_id, display_name, created_at) VALUES (?1, ?2, ?3)",
        params![tenant_id, display_name, now.secs()],
    )?;
    Ok(changed > 0)
}

/// False if the tenant is unknown or already disabled.
pub fn disable_tenant(
    conn: &Connection,
    tenant_id: &str,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "UPDATE tenant SET disabled_at = ?1 WHERE tenant_id = ?2 AND disabled_at IS NULL",
        params![now.secs(), tenant_id],
    )?;
    Ok(changed > 0)
}

pub fn tenant_is_disabled(conn: &Connection, tenant_id: &str) -> Result<bool, RepoError> {
    let disabled: Option<Option<i64>> = conn
        .query_row(
            "SELECT disabled_at FROM tenant WHERE tenant_id = ?1",
            params![tenant_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(matches!(disabled, Some(Some(_))))
}

/// Make sure `tenant_id` exists, creating it if nobody has, and report whether
/// it is enabled. Naming a tenant is all it takes to have one; a disabled one
/// is not resurrected by being named again.
fn ensure_tenant(conn: &Connection, tenant_id: &str, now: Timestamp) -> Result<bool, RepoError> {
    insert_tenant(conn, tenant_id, None, now)?;
    Ok(!tenant_is_disabled(conn, tenant_id)?)
}

/// A principal secret on its way to the store. Only the hash is kept.
pub struct NewSecret {
    pub secret_id: String,
    pub hash: Vec<u8>,
    pub expires_at: Option<Timestamp>,
}

impl std::fmt::Debug for NewSecret {
    // Rides inside `AdminWrite`, which derives `Debug` (INV-12).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSecret")
            .field("secret_id", &self.secret_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct NewPrincipal {
    pub principal_id: String,
    pub tenant_id: String,
    pub name: String,
    pub kind: String,
    pub scopes: Vec<String>,
    pub indexes: Vec<String>,
    pub audience: String,
    pub max_ttl_secs: u64,
    pub created_by: Option<String>,
    /// A principal is born with its first secret, in the same transaction.
    pub secret: NewSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRow {
    pub principal_id: String,
    pub tenant_id: String,
    pub name: String,
    pub kind: String,
    pub scopes: Vec<String>,
    pub indexes: Vec<String>,
    pub audience: String,
    pub max_ttl_secs: u64,
    pub created_at: Timestamp,
    pub created_by: Option<String>,
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRow {
    pub secret_id: String,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl SecretRow {
    /// The same rule [`find_live_principal_by_secret`] applies in SQL, so a
    /// listing and the token lane cannot disagree about what "live" means.
    pub fn live_at(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|at| at > now)
    }
}

const PRINCIPAL_COLUMNS: &str = "p.principal_id, p.tenant_id, p.name, p.kind, p.scope, p.indexes, \
     p.audience, p.max_ttl_secs, p.created_at, p.created_by, p.last_used_at, p.revoked_at";

fn json_list(raw: String, column: &str) -> Result<Vec<String>, RepoError> {
    serde_json::from_str(&raw)
        .map_err(|e| RepoError::Corrupt(format!("{column} is not a JSON array of strings: {e}")))
}

fn principal_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<PrincipalRow, RepoError>> {
    let scope: String = r.get(4)?;
    let indexes: String = r.get(5)?;
    let max_ttl: i64 = r.get(7)?;
    Ok((|| -> Result<PrincipalRow, RepoError> {
        Ok(PrincipalRow {
            principal_id: r.get(0)?,
            tenant_id: r.get(1)?,
            name: r.get(2)?,
            kind: r.get(3)?,
            scopes: json_list(scope, "principal.scope")?,
            indexes: json_list(indexes, "principal.indexes")?,
            audience: r.get(6)?,
            max_ttl_secs: max_ttl.max(0) as u64,
            created_at: Timestamp(r.get(8)?),
            created_by: r.get(9)?,
            last_used_at: r.get::<_, Option<i64>>(10)?.map(Timestamp),
            revoked_at: r.get::<_, Option<i64>>(11)?.map(Timestamp),
        })
    })())
}

fn insert_secret(
    conn: &Connection,
    principal_id: &str,
    secret: &NewSecret,
    now: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "INSERT INTO principal_secret (secret_id, principal_id, secret_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            secret.secret_id,
            principal_id,
            secret.hash,
            now.secs(),
            secret.expires_at.map(Timestamp::secs),
        ],
    )?;
    Ok(())
}

/// Create a principal and its first secret, creating the tenant if it is
/// missing. False if the tenant is disabled or the tenant already has a
/// principal of that name (revoked ones keep their name).
pub fn insert_principal(
    conn: &Connection,
    p: &NewPrincipal,
    now: Timestamp,
) -> Result<bool, RepoError> {
    if !ensure_tenant(conn, &p.tenant_id, now)? {
        return Ok(false);
    }
    let inserted = conn.execute(
        "INSERT INTO principal (principal_id, tenant_id, name, kind, scope, indexes, audience,
                                max_ttl_secs, created_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT (tenant_id, name) DO NOTHING",
        params![
            p.principal_id,
            p.tenant_id,
            p.name,
            p.kind,
            serde_json::to_string(&p.scopes).map_err(|e| RepoError::Corrupt(e.to_string()))?,
            serde_json::to_string(&p.indexes).map_err(|e| RepoError::Corrupt(e.to_string()))?,
            p.audience,
            p.max_ttl_secs as i64,
            now.secs(),
            p.created_by,
        ],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    insert_secret(conn, &p.principal_id, &p.secret, now)?;
    Ok(true)
}

/// Every principal, newest first, optionally of one tenant.
pub fn list_principals(
    conn: &Connection,
    tenant_id: Option<&str>,
) -> Result<Vec<PrincipalRow>, RepoError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {PRINCIPAL_COLUMNS} FROM principal p
         WHERE (?1 IS NULL OR p.tenant_id = ?1)
         ORDER BY p.created_at DESC, p.rowid DESC"
    ))?;
    let rows = stmt.query_map(params![tenant_id], principal_row)?;
    rows.map(|r| r.map_err(RepoError::from).and_then(std::convert::identity))
        .collect()
}

pub fn get_principal(
    conn: &Connection,
    principal_id: &str,
) -> Result<Option<PrincipalRow>, RepoError> {
    conn.query_row(
        &format!("SELECT {PRINCIPAL_COLUMNS} FROM principal p WHERE p.principal_id = ?1"),
        params![principal_id],
        principal_row,
    )
    .optional()?
    .transpose()
}

/// Every secret of a principal, newest first. Hashes stay in the store.
pub fn list_principal_secrets(
    conn: &Connection,
    principal_id: &str,
) -> Result<Vec<SecretRow>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT secret_id, created_at, expires_at, revoked_at FROM principal_secret
         WHERE principal_id = ?1 ORDER BY created_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map(params![principal_id], |r| {
        Ok(SecretRow {
            secret_id: r.get(0)?,
            created_at: Timestamp(r.get(1)?),
            expires_at: r.get::<_, Option<i64>>(2)?.map(Timestamp),
            revoked_at: r.get::<_, Option<i64>>(3)?.map(Timestamp),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(RepoError::from)
}

/// False if the principal is unknown or already revoked.
pub fn revoke_principal(
    conn: &Connection,
    principal_id: &str,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "UPDATE principal SET revoked_at = ?1 WHERE principal_id = ?2 AND revoked_at IS NULL",
        params![now.secs(), principal_id],
    )?;
    Ok(changed > 0)
}

/// Add a secret to a live principal. The principal's other secrets stay valid
/// untouched; only when `expire_others_at` is given are they dated, and only
/// the ones that would otherwise outlive that date — a secret already due to
/// expire sooner keeps its earlier date. False if the principal is unknown or
/// revoked.
pub fn add_principal_secret(
    conn: &Connection,
    principal_id: &str,
    secret: &NewSecret,
    expire_others_at: Option<Timestamp>,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let live: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM principal WHERE principal_id = ?1 AND revoked_at IS NULL",
            params![principal_id],
            |r| r.get(0),
        )
        .optional()?;
    if live.is_none() {
        return Ok(false);
    }
    if let Some(at) = expire_others_at {
        // Before the insert, so the new secret is not among "the others".
        conn.execute(
            "UPDATE principal_secret SET expires_at = ?1
             WHERE principal_id = ?2 AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?1)",
            params![at.secs(), principal_id],
        )?;
    }
    insert_secret(conn, principal_id, secret, now)?;
    Ok(true)
}

/// False if the secret is not one of this principal's, or already revoked.
pub fn revoke_principal_secret(
    conn: &Connection,
    principal_id: &str,
    secret_id: &str,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "UPDATE principal_secret SET revoked_at = ?1
         WHERE secret_id = ?2 AND principal_id = ?3 AND revoked_at IS NULL",
        params![now.secs(), secret_id, principal_id],
    )?;
    Ok(changed > 0)
}

/// Resolve a presented secret's hash to the principal it authenticates.
///
/// Four terms, each a way a still-stored secret stops working: the secret is
/// revoked, the secret has passed its `expires_at`, the principal is revoked,
/// the tenant is disabled. `now` comes from the caller's `Clock`.
pub fn find_live_principal_by_secret(
    conn: &Connection,
    secret_hash: &[u8],
    now: Timestamp,
) -> Result<Option<PrincipalRow>, RepoError> {
    conn.query_row(
        &format!(
            "SELECT {PRINCIPAL_COLUMNS}
             FROM principal_secret s
             JOIN principal p ON p.principal_id = s.principal_id
             JOIN tenant t ON t.tenant_id = p.tenant_id
             WHERE s.secret_hash = ?1
               AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > ?2)
               AND p.revoked_at IS NULL
               AND t.disabled_at IS NULL"
        ),
        params![secret_hash, now.secs()],
        principal_row,
    )
    .optional()?
    .transpose()
}

/// Record that a principal was issued a token. Deliberately unconditional: it
/// is sent only after the secret resolved, and a principal revoked a moment
/// later still shows when it was last used.
pub fn touch_principal(
    conn: &Connection,
    principal_id: &str,
    now: Timestamp,
) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE principal SET last_used_at = ?1 WHERE principal_id = ?2",
        params![now.secs(), principal_id],
    )?;
    Ok(())
}

#[derive(Debug)]
pub struct NewUserGrant {
    pub sub: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub indexes: Vec<String>,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserGrantRow {
    pub sub: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub indexes: Vec<String>,
    pub created_at: Timestamp,
    pub created_by: Option<String>,
    pub revoked_at: Option<Timestamp>,
}

/// Grant `sub` a tenant, creating the tenant if it is missing. The key is
/// `(sub, tenant)`, so a revoked grant is brought back to life with the new
/// roles rather than blocking the pair for good. False if a live grant already
/// exists or the tenant is disabled.
pub fn insert_user_grant(
    conn: &Connection,
    g: &NewUserGrant,
    now: Timestamp,
) -> Result<bool, RepoError> {
    if !ensure_tenant(conn, &g.tenant_id, now)? {
        return Ok(false);
    }
    let changed = conn.execute(
        "INSERT INTO user_grant (sub, tenant_id, roles, indexes, created_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (sub, tenant_id) DO UPDATE SET
           roles = excluded.roles, indexes = excluded.indexes,
           created_at = excluded.created_at, created_by = excluded.created_by,
           revoked_at = NULL
         WHERE user_grant.revoked_at IS NOT NULL",
        params![
            g.sub,
            g.tenant_id,
            serde_json::to_string(&g.roles).map_err(|e| RepoError::Corrupt(e.to_string()))?,
            serde_json::to_string(&g.indexes).map_err(|e| RepoError::Corrupt(e.to_string()))?,
            now.secs(),
            g.created_by,
        ],
    )?;
    Ok(changed > 0)
}

fn user_grant_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<UserGrantRow, RepoError>> {
    let roles: String = r.get(2)?;
    let indexes: String = r.get(3)?;
    Ok((|| -> Result<UserGrantRow, RepoError> {
        Ok(UserGrantRow {
            sub: r.get(0)?,
            tenant_id: r.get(1)?,
            roles: json_list(roles, "user_grant.roles")?,
            indexes: json_list(indexes, "user_grant.indexes")?,
            created_at: Timestamp(r.get(4)?),
            created_by: r.get(5)?,
            revoked_at: r.get::<_, Option<i64>>(6)?.map(Timestamp),
        })
    })())
}

/// Every grant, newest first, optionally of one tenant and/or one subject.
pub fn list_user_grants(
    conn: &Connection,
    tenant_id: Option<&str>,
    sub: Option<&str>,
) -> Result<Vec<UserGrantRow>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT sub, tenant_id, roles, indexes, created_at, created_by, revoked_at
         FROM user_grant
         WHERE (?1 IS NULL OR tenant_id = ?1) AND (?2 IS NULL OR sub = ?2)
         ORDER BY created_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map(params![tenant_id, sub], user_grant_row)?;
    rows.map(|r| r.map_err(RepoError::from).and_then(std::convert::identity))
        .collect()
}

/// The grants `sub` can be issued a token on right now: not revoked, and the
/// tenant not disabled. Newest first.
pub fn find_live_user_grants(conn: &Connection, sub: &str) -> Result<Vec<UserGrantRow>, RepoError> {
    let mut stmt = conn.prepare(
        "SELECT g.sub, g.tenant_id, g.roles, g.indexes, g.created_at, g.created_by, g.revoked_at
         FROM user_grant g JOIN tenant t ON t.tenant_id = g.tenant_id
         WHERE g.sub = ?1 AND g.revoked_at IS NULL AND t.disabled_at IS NULL
         ORDER BY g.created_at DESC, g.rowid DESC",
    )?;
    let rows = stmt.query_map(params![sub], user_grant_row)?;
    rows.map(|r| r.map_err(RepoError::from).and_then(std::convert::identity))
        .collect()
}

/// False if there is no live grant for the pair.
pub fn revoke_user_grant(
    conn: &Connection,
    sub: &str,
    tenant_id: &str,
    now: Timestamp,
) -> Result<bool, RepoError> {
    let changed = conn.execute(
        "UPDATE user_grant SET revoked_at = ?1
         WHERE sub = ?2 AND tenant_id = ?3 AND revoked_at IS NULL",
        params![now.secs(), sub, tenant_id],
    )?;
    Ok(changed > 0)
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
            seal(refresh_tok, &context(&custody_id.0, "refresh")),
            seal(access_tok, &context(&custody_id.0, "access")),
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
/// Kill a session durably (INV-7).
///
/// `now` is stamped into `tombstoned_at` so the reaper has something to measure
/// a retention window against. `COALESCE` keeps the FIRST death: logout is
/// idempotent, and letting a retry push the timestamp forward would let a
/// client keep a dead row alive indefinitely by retrying.
pub fn tombstone_session(conn: &Connection, sid: &Sid, now: Timestamp) -> Result<(), RepoError> {
    conn.execute(
        "UPDATE session
            SET status = 'tombstoned',
                tombstoned_at = COALESCE(tombstoned_at, ?2)
          WHERE sid = ?1",
        params![sid.0, now.secs()],
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
// reaper (M6)
//
// The ONLY place that removes session, generation, txn or custody rows.
// Everything here is deliberately conservative: this is a delete path in a
// service where deleting the wrong row logs a real person out.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReapOutcome {
    pub generations: usize,
    pub sessions: usize,
    pub txns: usize,
    pub custodies: usize,
}

impl ReapOutcome {
    pub fn is_empty(&self) -> bool {
        *self == ReapOutcome::default()
    }
}

/// Remove what is provably dead.
///
/// Three independent predicates, each safe on its own:
///
/// * a session tombstoned longer ago than `dead_before` — it is already
///   unreachable (`rehydrate` loads only `alive` rows, and INV-7 means every
///   generation died with it);
/// * a session whose `absolute_exp` is past `dead_before` — the hard ceiling has
///   passed, so no cookie for it can ever authenticate again, tombstoned or not;
/// * a txn older than `txn_before` — INV-3's 10-minute single-use window.
///
/// A tombstoned row with a NULL `tombstoned_at` (killed before schema v4) is
/// judged on `absolute_exp` alone. Treating unknown as "old enough" would delete
/// on a guess, and this is not the code to guess in.
///
/// Custody rows go last and only when NO session references them: the FK points
/// that way, one custody can back several sessions, and an orphaned custody is
/// both dead weight and an encrypted refresh token nobody can use — so removing
/// it shrinks the credential material at rest.
///
/// **The audit record is what survives this.** Reaping a session removes the row
/// that a session existed; `session.created` / `session.logged_out` in the
/// `audit` table are the history, and they have their own, longer retention.
pub fn reap(
    conn: &Connection,
    dead_before: Timestamp,
    txn_before: Timestamp,
) -> Result<ReapOutcome, RepoError> {
    const DOOMED: &str = "SELECT sid FROM session
                           WHERE (status = 'tombstoned' AND tombstoned_at IS NOT NULL
                                  AND tombstoned_at < ?1)
                              OR absolute_exp < ?1";

    // Generations first: `generation.sid` is a foreign key onto `session`, and
    // `foreign_keys` is ON, so the other order fails the whole transaction.
    let generations = conn.execute(
        &format!("DELETE FROM generation WHERE sid IN ({DOOMED})"),
        params![dead_before.secs()],
    )?;
    let sessions = conn.execute(
        &format!("DELETE FROM session WHERE sid IN ({DOOMED})"),
        params![dead_before.secs()],
    )?;
    let txns = conn.execute(
        "DELETE FROM txn WHERE created_at < ?1",
        params![txn_before.secs()],
    )?;
    let custodies = conn.execute(
        "DELETE FROM custody
          WHERE custody_id NOT IN (SELECT custody_id FROM session)",
        [],
    )?;

    Ok(ReapOutcome {
        generations,
        sessions,
        txns,
        custodies,
    })
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

pub fn list_audit(conn: &Connection, query: &AuditQuery) -> Result<Vec<StoredAuditRow>, RepoError> {
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
    let (rows, oldest, newest): (i64, Option<i64>, Option<i64>) =
        conn.query_row("SELECT COUNT(*), MIN(at), MAX(at) FROM audit", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
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
    fn reseal_moves_rows_off_a_retired_key_and_leaves_unreadable_ones_alone() {
        let conn = store::open_in_memory().unwrap();
        let now = Timestamp(1_700_000_000);
        insert_custody(&conn, &custody_row("cust-old", now)).unwrap();
        insert_custody(&conn, &custody_row("cust-bad", now)).unwrap();

        // The process ring plus one newer key: the state right after `rotate-key`.
        // The rows were just written under the older key.
        let rotated = crate::store::crypto::rotated_for_test();
        let report = reseal_custody_with(&conn, &rotated).unwrap();
        assert_eq!(report.resealed, 2);
        let raw: Vec<u8> = conn
            .query_row(
                "SELECT refresh_tok FROM custody WHERE custody_id = 'cust-old'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(key_id_of(&raw), Some(2));
        let again = reseal_custody_with(&conn, &rotated).unwrap();
        assert_eq!(
            (again.resealed, again.current),
            (0, 2),
            "a second pass is a no-op"
        );

        // A row that cannot be opened is counted and NOT rewritten.
        conn.execute(
            "UPDATE custody SET refresh_tok = x'0101ffff' WHERE custody_id = 'cust-bad'",
            [],
        )
        .unwrap();
        let failed = reseal_custody_with(&conn, &rotated).unwrap();
        assert_eq!(failed.failed, 1);
        let kept: Vec<u8> = conn
            .query_row(
                "SELECT refresh_tok FROM custody WHERE custody_id = 'cust-bad'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, vec![1, 1, 255, 255]);
    }

    /// The boot `Reseal` must reach `signing_key.seed_sealed` as well as the
    /// custody columns. Driven through `reseal_all_with` — the function the
    /// writer's `Reseal` runs, with the ring swapped — so a table left out of
    /// it fails here.
    #[test]
    fn reseal_moves_a_signing_seed_onto_a_rotated_custody_key() {
        let conn = store::open_in_memory().unwrap();
        let now = Timestamp(1_700_000_000);
        let key = crate::issuer::keys::generate();
        let seed = *key.seed;
        insert_signing_key(&conn, &key, now, now).unwrap();
        insert_custody(&conn, &custody_row("cust-1", now)).unwrap();
        let sealed = |conn: &Connection| -> Vec<u8> {
            conn.query_row("SELECT seed_sealed FROM signing_key", [], |r| r.get(0))
                .unwrap()
        };
        let before = sealed(&conn);
        assert_eq!(key_id_of(&before), Some(1));

        let rotated = crate::store::crypto::rotated_for_test();
        let report = reseal_all_with(&conn, &rotated).unwrap();
        assert_eq!(report.signing_keys.resealed, 1);
        assert_eq!(report.custody.resealed, 1);

        let after = sealed(&conn);
        assert_eq!(key_id_of(&after), Some(rotated.active_id()));
        assert_ne!(after, before);
        // Same seed, same row binding, now under the new key.
        assert_eq!(
            rotated
                .open(&after, &signing_seed_context(&key.kid))
                .unwrap(),
            seed
        );
        assert!(rotated
            .open(&after, &signing_seed_context("other"))
            .is_err());

        let again = reseal_all_with(&conn, &rotated).unwrap();
        assert_eq!(
            (again.signing_keys.resealed, again.signing_keys.current),
            (0, 1),
            "a second pass is a no-op"
        );

        // A seed that cannot be opened is counted and left as it was.
        conn.execute("UPDATE signing_key SET seed_sealed = x'0101ffff'", [])
            .unwrap();
        let failed = reseal_all_with(&conn, &rotated).unwrap();
        assert_eq!(failed.signing_keys.failed, 1);
        assert_eq!(sealed(&conn), vec![1, 1, 255, 255]);
        // And the issuer's load reports it as unusable instead of failing.
        let loaded = load_signing_keys(&conn).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].1.is_none());
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
