//! Schema and forward-only migrations for the embedded SQLite store (§5).
//!
//! **One surface, no trait.** Storage is a concrete SQL schema accessed
//! exclusively through [`repo`]'s free functions — deliberately no storage
//! trait and no backend pluralism (ADR-0005). A later Postgres port is an
//! edit to `repo`'s function bodies and a migration file, not an API
//! change; see the module docs on [`repo`] and [`writer`].
//!
//! **The memory/durability split.** Session and generation rows are
//! write-behind: [`writer`] batches them into transactions on its own
//! schedule and the caller does not wait. Custody rows are write-through:
//! the irreplaceable upstream refresh token must hit disk before the
//! keepalive worker (a later milestone) acts on having rotated it (§6). This
//! module only owns getting a `Connection` into a state both paths can rely
//! on: WAL journalling, `foreign_keys` enforcement, and migrations applied.

use std::path::Path;

use rusqlite::Connection;

pub mod crypto;
pub mod repo;
pub mod writer;

/// Schema version this binary knows how to reach. Bump this and append to
/// [`MIGRATIONS`] together — the two must stay the same length.
pub const SCHEMA_VERSION: i64 = 3;

/// Forward-only migration steps, applied in order inside one transaction at
/// boot. `store::migrate` tracks how far a given database file has already
/// come in a `schema_version` table, so re-running this list on every boot
/// (including against an already-current file) is always safe — the
/// "restart story" in §5 depends on that idempotence.
const MIGRATIONS: &[&str] = &[
    // v1 — the schema from docs/architecture/implementation-strategy.md §5,
    // verbatim: table and column names are load-bearing because the rest of
    // the system (and its docs) refer to them directly.
    r#"
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
    "#,
    // v2 — backend API keys as data rather than one static config value, so
    // they can be named, rotated and revoked without a redeploy (ADR-0013).
    //
    // `key_hash` is SHA-256 of the secret, and the secret itself is never
    // stored: a key is shown exactly once, at creation. That is the whole
    // reason this table can be read by an admin console at all — listing keys
    // reveals who holds access, not the access itself.
    r#"
    CREATE TABLE api_key (
      key_id       TEXT PRIMARY KEY,      -- public, safe to display and log
      name         TEXT NOT NULL,         -- which backend this belongs to
      key_hash     BLOB NOT NULL UNIQUE,  -- sha256(secret); the secret is never stored
      created_at   INTEGER NOT NULL,
      created_by   TEXT,                  -- the admin subject, for the audit trail
      last_used_at INTEGER,
      revoked_at   INTEGER                -- NULL means live
    );
    CREATE INDEX api_key_live ON api_key(key_hash) WHERE revoked_at IS NULL;
    "#,
    // v3 — the audit record (ADR-0015). A table, not a log stream: a record
    // whose completeness depends on a sidecar's configuration cannot answer
    // "prove nobody issued a key that week".
    //
    // `AUTOINCREMENT` is load-bearing and not just a primary key. SQLite's
    // default rowid reuses the largest deleted value; with retention pruning
    // that would let `seq` go backwards after a prune, breaking both the
    // pagination cursor and the ability to read a gap in the sequence as
    // evidence rather than ambiguity.
    //
    // Append-only by policy and by test: nothing in `repo` issues UPDATE on
    // this table, and the only DELETE is the retention prune.
    r#"
    CREATE TABLE audit (
      seq              INTEGER PRIMARY KEY AUTOINCREMENT,
      at               INTEGER NOT NULL,   -- epoch secs
      action           TEXT    NOT NULL,   -- stable dotted name (audit::action)
      outcome          TEXT    NOT NULL,   -- success | failure
      actor_kind       TEXT    NOT NULL,   -- admin | backend | user | system | anonymous
      actor_id         TEXT,               -- key_id, sub, or NULL
      subject          TEXT,               -- whose data was acted on
      sid              TEXT,
      custody_id       TEXT,
      key_id           TEXT,
      reason           TEXT,               -- the refusal code, on failure
      client_ip_prefix TEXT,               -- /24 or /48 only, never a full address (INV-12)
      detail           TEXT                -- non-secret JSON
    );
    CREATE INDEX audit_by_time ON audit(at DESC);
    CREATE INDEX audit_by_action ON audit(action, at DESC);
    CREATE INDEX audit_by_subject ON audit(subject, at DESC);
    "#,
];

/// Open (creating if absent) the on-disk store at `path`, in WAL mode with
/// migrations already applied and the custody encryption key loaded from
/// `keyfile`.
///
/// The keyfile is loaded HERE, rather than by a separate boot step, so there
/// is no reachable state in which a caller holds a `Connection` whose custody
/// columns cannot be sealed. A separate `init_encryption()` would be a step a
/// future boot path could omit, and the symptom of omitting it — upstream
/// refresh tokens written in plaintext — is invisible until someone reads the
/// file.
pub fn open(path: &Path, keyfile: &Path) -> rusqlite::Result<Connection> {
    crypto::init_from_keyfile(keyfile).map_err(|e| {
        rusqlite::Error::InvalidPath(std::path::PathBuf::from(format!(
            "custody keyfile {}: {e}",
            keyfile.display()
        )))
    })?;
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// An in-memory store for tests that don't need to survive a process
/// restart. `journal_mode=WAL` is a no-op on `:memory:` databases (SQLite
/// silently keeps `memory` journalling); everything else still applies.
///
/// Custody encryption uses a process-lifetime random key: nothing here
/// outlives the process, so there is no key to lose, and seal/open still
/// behave exactly as they do in production rather than degrading to plaintext
/// under test — which would leave the encryption path untested.
pub fn open_in_memory() -> rusqlite::Result<Connection> {
    crypto::init_ephemeral();
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// A shared read handle.
///
/// All *writes* funnel through [`writer`]'s single thread (§5). Reads do not
/// need to: WAL journalling lets readers run concurrently with the writer
/// without blocking it, so a second connection behind a mutex is enough for
/// the two read paths that exist off the hot path — the keepalive worker
/// loading a custody row before refreshing it, and `/internal/token` answering
/// a backend.
///
/// The session hot path never comes here at all; it is served from the
/// in-memory map, which is the whole point of the memory-primary design.
pub struct Reader {
    conn: std::sync::Mutex<Connection>,
}

impl Reader {
    pub fn new(conn: Connection) -> Reader {
        Reader {
            conn: std::sync::Mutex::new(conn),
        }
    }

    /// Run `f` against the read connection. Panics only if a previous reader
    /// panicked mid-query, which would mean the connection's state is unknown.
    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        let guard = self.conn.lock().expect("store reader mutex poisoned");
        f(&guard)
    }
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("store::Reader")
    }
}

fn apply_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// Bring `conn` forward to [`SCHEMA_VERSION`], tracked in a `schema_version`
/// table (one row per version applied). A no-op if the file is already
/// current — the case on every boot after the first.
fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")?;
    let current: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if current >= SCHEMA_VERSION {
        return Ok(());
    }

    let tx = conn.unchecked_transaction()?;
    for (i, step) in MIGRATIONS.iter().enumerate() {
        let version = (i + 1) as i64;
        if version <= current {
            continue;
        }
        tx.execute_batch(step)?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [version],
        )?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_idempotent_across_two_opens() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "session-broker-migrate-test-{}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let conn =
                open(&path, &path.with_extension("key")).expect("first open runs migrations");
            let version: i64 = conn
                .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
        }
        {
            // Second open on the same file must not try to re-create the
            // tables (which would error) or otherwise fail.
            let conn = open(&path, &path.with_extension("key"))
                .expect("second open must be a no-op, not an error");
            let version: i64 = conn
                .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(dir.join(format!(
            "session-broker-migrate-test-{}.sqlite3-wal",
            std::process::id()
        )));
        let _ = std::fs::remove_file(dir.join(format!(
            "session-broker-migrate-test-{}.sqlite3-shm",
            std::process::id()
        )));
    }

    #[test]
    fn opens_in_wal_mode_with_foreign_keys_on() {
        let conn = open_in_memory().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        // :memory: databases stay "memory" regardless of the WAL request —
        // asserting the pragma call didn't error is the point on-disk.
        assert!(mode == "memory" || mode == "wal");

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn schema_has_the_documented_tables() {
        let conn = open_in_memory().unwrap();
        for table in [
            "custody",
            "session",
            "generation",
            "txn",
            "api_key",
            "audit",
            "schema_version",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing table {table}");
        }
    }
}
