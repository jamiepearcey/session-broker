//! The single-writer task (§5): one dedicated OS thread owns the only
//! `rusqlite::Connection` that ever writes, fed by an MPSC channel of
//! mutation [`Command`]s and batching whatever has arrived since the last
//! flush into one SQLite transaction, at most every [`FLUSH_INTERVAL`].
//!
//! `rusqlite` is sync on purpose (§7: "a dedicated writer thread + channel is
//! simpler and faster than an async pool for a single-writer workload") — no
//! attempt is made to make it async here, and this module reaches for
//! nothing beyond `std::sync::mpsc` and `std::thread`.
//!
//! **Write-behind vs write-through.** Session/generation mutations
//! ([`WriterHandle::enqueue`]) return immediately — the in-memory
//! `SessionMap` (a later milestone) is the read path, and losing the last
//! few milliseconds of writes in a crash is safe because rotation is
//! non-invalidating (§5, §6). Custody mutations
//! ([`WriterHandle::write_custody`]) block the caller until the batch's
//! transaction has committed, because an unacknowledged refresh-token
//! rotation is the hazard called out in §6: the keepalive worker must not
//! believe a new refresh token is durable until this call returns `Ok`.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::Connection;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use super::repo::{self, AuditRow, CustodyRow, RepoError, SessionRow, TxnRow};
use crate::clock::Timestamp;
use crate::session::{CustodyId, CustodyStatus, Sid};
use crate::token::TokenHash;

/// Upper bound on how long a mutation can sit unflushed (§5: "≤50 ms flush
/// interval"). Not a lower bound — a burst of custody writes flushes
/// immediately because the writer drains whatever is already queued before
/// committing.
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);

/// The durability signal for a write-through custody command: `Ok(())` once
/// the batch transaction containing it has committed, `Err` with a
/// description if the batch failed (in which case none of it committed) or
/// the writer thread is gone.
pub type DurabilityAck = mpsc::Sender<Result<(), String>>;

/// The admin lane's ack: `Ok(true)` acted, `Ok(false)` there was nothing to act
/// on (a 404, not a failure).
pub type AdminAck = mpsc::Sender<Result<bool, String>>;

/// What one batch produced: the transaction's result, the custody acks to
/// settle, the admin acks to settle with their outcomes, and whether the writer
/// was asked to stop.
type BatchOutcome = (
    Result<(), RepoError>,
    Vec<DurabilityAck>,
    Vec<(AdminAck, bool)>,
    bool,
);

/// Custody mutations, the write-through half of the split. Kept as a
/// distinct type (rather than folded into [`Command`]) so
/// [`WriterHandle::write_custody`] can only be called with something that
/// actually carries an ack.
#[derive(Debug)]
pub enum CustodyWrite {
    Insert(CustodyRow),
    /// Keepalive success (§6): both tokens rotate, status resets to `ok`.
    Success {
        custody_id: CustodyId,
        refresh_tok: Vec<u8>,
        access_tok: Vec<u8>,
        access_exp: Timestamp,
        next_refresh: Timestamp,
        now: Timestamp,
    },
    /// Keepalive transient/permanent failure (§6): status and backoff
    /// schedule move, tokens do not.
    Failure {
        custody_id: CustodyId,
        status: CustodyStatus,
        fail_count: i64,
        next_refresh: Timestamp,
        now: Timestamp,
    },
}

/// Admin-lane mutations (`/admin/*`).
#[derive(Debug)]
pub enum AdminWrite {
    InsertApiKey {
        key_id: String,
        name: String,
        key_hash: Vec<u8>,
        created_by: Option<String>,
        now: Timestamp,
    },
    RevokeApiKey {
        key_id: String,
        now: Timestamp,
    },
    TouchApiKey {
        key_id: String,
        now: Timestamp,
    },
}

/// Write-behind mutations: session/generation/txn housekeeping. Enqueued and
/// forgotten by the caller.
#[derive(Debug)]
pub enum Command {
    InsertSession(SessionRow),
    /// The idle slide and generation counter, after a refresh.
    UpdateSessionProgress {
        sid: Sid,
        current_gen: u32,
        idle_exp: Timestamp,
    },
    TombstoneSession(Sid, Timestamp),
    InsertGeneration {
        sid: Sid,
        gen_no: u32,
        hash: TokenHash,
        created_at: Timestamp,
        active_until: Timestamp,
    },
    SupersedeGeneration {
        hash: TokenHash,
        superseded_at: Timestamp,
    },
    DeleteGeneration(TokenHash),
    InsertTxn(TxnRow),
    DeleteExpiredTxns(Timestamp),
    /// Write-through, carries its durability ack.
    Custody(CustodyWrite, DurabilityAck),
    /// Admin mutations. Write-through like custody, and for a related reason:
    /// an API key handed to an operator that did not reach disk, or a
    /// revocation reported as done that did not, are both worse than an error.
    /// The ack carries a bool because "revoked" and "there was nothing to
    /// revoke" are different answers.
    ///
    /// The optional [`AuditRow`] is **Tier A** (ADR-0015): it is applied inside
    /// the same transaction as the mutation, so there is no reachable state with
    /// the change but not the record, or the record but not the change. That is
    /// why it rides this command rather than being a separate write — proximity
    /// in time is not the guarantee; atomicity is.
    Admin(AdminWrite, Option<Box<AuditRow>>, AdminAck),
    /// **Tier B** audit (ADR-0015): write-behind, batched, depth-bounded.
    ///
    /// `depth` is decremented once the row has been applied. The sink compares
    /// it against `audit_queue_capacity` before enqueuing, which is what stops a
    /// stalled writer thread from turning into unbounded memory growth inside
    /// the process that holds every user's refresh token.
    Audit {
        row: Box<AuditRow>,
        depth: Arc<AtomicI64>,
    },
    /// Retention sweep for the audit record.
    PruneAudit(Timestamp),
    /// The reaper (M6): drop provably-dead session, generation, txn and
    /// orphaned custody rows. Write-behind — nothing waits on a deletion.
    Reap {
        dead_before: Timestamp,
        txn_before: Timestamp,
    },
    /// Internal: stop after committing whatever else is in this batch.
    Shutdown,
}

/// Owns the writer thread. Dropping it asks the thread to flush and stop,
/// then joins it — so a graceful process shutdown does not lose a queued
/// batch.
pub struct Writer {
    tx: Sender<Command>,
    handle: Option<JoinHandle<()>>,
}

impl Writer {
    /// Spawn the writer thread over `conn`, which must already have
    /// migrations applied (`store::open`/`store::open_in_memory`).
    pub fn spawn(conn: Connection) -> Writer {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("session-broker-writer".to_owned())
            .spawn(move || run(conn, rx))
            .expect("failed to spawn store writer thread");
        Writer {
            tx,
            handle: Some(handle),
        }
    }

    /// A cheaply cloneable sender for the mutation channel.
    pub fn handle(&self) -> WriterHandle {
        WriterHandle {
            tx: self.tx.clone(),
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// What the rest of the crate holds to talk to the writer. Cloneable —
/// every request handler and the keepalive worker get their own handle onto
/// the same underlying channel.
#[derive(Clone)]
pub struct WriterHandle {
    tx: Sender<Command>,
}

impl std::fmt::Debug for WriterHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriterHandle")
    }
}

impl WriterHandle {
    /// Write-behind: enqueue and return immediately.
    pub fn enqueue(&self, cmd: Command) {
        // A send failure here means the writer thread is gone (process
        // shutting down); there is nothing a write-behind caller can usefully
        // do about that, so it's dropped rather than propagated.
        let _ = self.tx.send(cmd);
    }

    /// Write-through: enqueue a custody mutation and block until its
    /// transaction has committed (or the batch failed). This is the call
    /// the §6 refresh-token-rotation hazard requires: do not update local
    /// scheduling state as if a rotated refresh token is safe until this
    /// returns `Ok`.
    pub fn write_custody(&self, write: CustodyWrite) -> Result<(), String> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(Command::Custody(write, ack_tx))
            .map_err(|_| "writer thread is gone".to_owned())?;
        ack_rx
            .recv()
            .map_err(|_| "writer thread dropped without acking".to_owned())?
    }

    /// Record that an issued key was used. Fire-and-forget: "last used" is
    /// operational colour, and a request must not fail because it could not be
    /// written.
    pub fn enqueue_touch(&self, key_id: &str, now: Timestamp) -> Result<(), String> {
        let (ack_tx, _ack_rx) = mpsc::channel();
        self.tx
            .send(Command::Admin(
                AdminWrite::TouchApiKey {
                    key_id: key_id.to_owned(),
                    now,
                },
                // Recording "a key was used" is what `last_used_at` is for; an
                // audit row per use would be the coalescing problem ADR-0015
                // solves for token exchange, without the audit value.
                None,
                ack_tx,
            ))
            .map_err(|_| "writer thread is gone".to_owned())
    }

    /// Persist a custody's health and backoff after a FAILED refresh.
    ///
    /// Fire-and-forget, deliberately unlike [`WriterHandle::write_custody`].
    /// The write-through rule in §6 exists for the irreplaceable refresh token:
    /// the worker must not believe a rotated one is durable until it is. A
    /// failure rotates nothing — only `status`, `fail_count` and `next_refresh`
    /// move — so the hazard does not apply, and losing the last one in a crash
    /// costs a single retry on a stale schedule.
    ///
    /// Blocking here would be actively worse: during an upstream outage every
    /// custody in the fleet fails at once, and an ack per failure would
    /// serialise the whole fleet's failure handling behind one fsync at exactly
    /// the moment the worker has the most to do.
    pub fn enqueue_custody_failure(
        &self,
        custody_id: CustodyId,
        status: CustodyStatus,
        fail_count: i64,
        next_refresh: Timestamp,
        now: Timestamp,
    ) {
        let (ack_tx, _ack_rx) = mpsc::channel();
        let _ = self.tx.send(Command::Custody(
            CustodyWrite::Failure {
                custody_id,
                status,
                fail_count,
                next_refresh,
                now,
            },
            ack_tx,
        ));
    }

    /// Write-through admin mutation. `Ok(false)` means the row was not there to
    /// change — a 404, not a failure.
    pub fn write_admin(&self, write: AdminWrite) -> Result<bool, String> {
        self.write_admin_audited(write, None)
    }

    /// Write-through admin mutation with its Tier-A audit row, applied in the
    /// same transaction.
    ///
    /// If the transaction fails, both are lost together and the caller gets an
    /// `Err` it must turn into a refusal — which is the fail-closed half of
    /// ADR-0015: refuse to act rather than act unrecorded.
    pub fn write_admin_audited(
        &self,
        write: AdminWrite,
        audit: Option<AuditRow>,
    ) -> Result<bool, String> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(Command::Admin(write, audit.map(Box::new), ack_tx))
            .map_err(|_| "writer thread is gone".to_owned())?;
        ack_rx
            .recv()
            .map_err(|_| "writer thread dropped without acking".to_owned())?
    }
}

fn run(conn: Connection, rx: Receiver<Command>) {
    loop {
        let first = match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(cmd) => cmd,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };

        let mut batch = vec![first];
        // Drain whatever else has queued up without waiting for it — this
        // is the batching: a burst of concurrent writers converges on one
        // transaction instead of one each.
        while let Ok(cmd) = rx.try_recv() {
            batch.push(cmd);
        }

        let (result, acks, admin_acks, shutdown) = apply_batch(&conn, batch);
        match result {
            Ok(()) => {
                for ack in acks {
                    let _ = ack.send(Ok(()));
                }
                for (ack, outcome) in admin_acks {
                    let _ = ack.send(Ok(outcome));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "store writer batch failed; transaction rolled back");
                let msg = e.to_string();
                for ack in acks {
                    let _ = ack.send(Err(msg.clone()));
                }
                for (ack, _) in admin_acks {
                    let _ = ack.send(Err(msg.clone()));
                }
            }
        }

        if shutdown {
            return;
        }
    }
}

/// Apply every command in `batch` inside one transaction. All-or-nothing:
/// if any statement fails the transaction is dropped without committing
/// (rusqlite rolls back on drop), and every custody ack in the batch sees
/// the same failure — which is correct, since none of it is durable.
fn apply_batch(conn: &Connection, batch: Vec<Command>) -> BatchOutcome {
    let mut acks = Vec::new();
    let mut admin_acks = Vec::new();
    let mut shutdown = false;

    // Release the sink's depth accounting for every audit command in this
    // batch, up front and unconditionally.
    //
    // Doing it here rather than inside the transaction is the point: a `?` in
    // the middle of the loop below drops the remaining commands unprocessed,
    // and a depth that was incremented on enqueue but never decremented would
    // ratchet the sink towards a permanent "queue full" state — dropping every
    // audit event forever after one bad batch. The bound exists to survive a
    // stall, not to be armed by one.
    for cmd in &batch {
        if let Command::Audit { depth, .. } = cmd {
            depth.fetch_sub(1, Ordering::Relaxed);
        }
    }

    let result = (|| -> Result<(), RepoError> {
        let tx = conn.unchecked_transaction()?;
        for cmd in batch {
            match cmd {
                Command::InsertSession(row) => {
                    repo::insert_session(&tx, &row)?;
                }
                Command::UpdateSessionProgress {
                    sid,
                    current_gen,
                    idle_exp,
                } => {
                    repo::update_session_progress(&tx, &sid, current_gen, idle_exp)?;
                }
                Command::TombstoneSession(sid, now) => {
                    repo::tombstone_session(&tx, &sid, now)?;
                }
                Command::InsertGeneration {
                    sid,
                    gen_no,
                    hash,
                    created_at,
                    active_until,
                } => {
                    repo::insert_generation(&tx, &sid, gen_no, &hash, created_at, active_until)?;
                }
                Command::SupersedeGeneration {
                    hash,
                    superseded_at,
                } => {
                    repo::update_generation_superseded(&tx, &hash, superseded_at)?;
                }
                Command::DeleteGeneration(hash) => {
                    repo::delete_generation(&tx, &hash)?;
                }
                Command::InsertTxn(row) => {
                    repo::insert_txn(&tx, &row)?;
                }
                Command::DeleteExpiredTxns(before) => {
                    repo::delete_expired_txns(&tx, before)?;
                }
                Command::Custody(write, ack) => {
                    match write {
                        CustodyWrite::Insert(row) => repo::insert_custody(&tx, &row)?,
                        CustodyWrite::Success {
                            custody_id,
                            refresh_tok,
                            access_tok,
                            access_exp,
                            next_refresh,
                            now,
                        } => repo::update_custody_success(
                            &tx,
                            &custody_id,
                            &refresh_tok,
                            &access_tok,
                            access_exp,
                            next_refresh,
                            now,
                        )?,
                        CustodyWrite::Failure {
                            custody_id,
                            status,
                            fail_count,
                            next_refresh,
                            now,
                        } => repo::update_custody_failure(
                            &tx,
                            &custody_id,
                            status,
                            fail_count,
                            next_refresh,
                            now,
                        )?,
                    }
                    acks.push(ack);
                }
                Command::Audit { row, .. } => {
                    repo::insert_audit(&tx, &row)?;
                }
                Command::Reap {
                    dead_before,
                    txn_before,
                } => {
                    let reaped = repo::reap(&tx, dead_before, txn_before)?;
                    if !reaped.is_empty() {
                        tracing::info!(
                            target: "broker::reaper",
                            sessions = reaped.sessions,
                            generations = reaped.generations,
                            txns = reaped.txns,
                            custodies = reaped.custodies,
                            "reaped dead rows"
                        );
                    }
                }
                Command::PruneAudit(before) => {
                    let removed = repo::prune_audit(&tx, before)?;
                    if removed > 0 {
                        tracing::info!(
                            target: "broker::audit",
                            removed,
                            before = before.secs(),
                            "audit retention sweep"
                        );
                    }
                }
                Command::Admin(write, audit, ack) => {
                    let outcome = match write {
                        AdminWrite::InsertApiKey {
                            key_id,
                            name,
                            key_hash,
                            created_by,
                            now,
                        } => repo::insert_api_key(
                            &tx,
                            &key_id,
                            &name,
                            &key_hash,
                            created_by.as_deref(),
                            now,
                        )
                        .map(|()| true),
                        AdminWrite::RevokeApiKey { key_id, now } => {
                            repo::revoke_api_key(&tx, &key_id, now)
                        }
                        AdminWrite::TouchApiKey { key_id, now } => {
                            repo::touch_api_key(&tx, &key_id, now).map(|()| true)
                        }
                    }?;

                    // Tier A: same transaction as the mutation, so there is no
                    // reachable state with one and not the other.
                    //
                    // Written AFTER the mutation, and carrying its result: a
                    // revoke that matched no row must not leave a row saying a
                    // key was revoked. "Nothing to revoke" is a real answer and
                    // the record has to give the same one the caller got.
                    if let Some(mut row) = audit {
                        if !outcome {
                            row.outcome = "failure".to_owned();
                            row.reason = Some("not_found".to_owned());
                        }
                        repo::insert_audit(&tx, &row)?;
                    }
                    admin_acks.push((ack, outcome));
                }
                Command::Shutdown => {
                    shutdown = true;
                }
            }
        }
        tx.commit()?;
        Ok(())
    })();

    (result, acks, admin_acks, shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    fn custody_row(id: &str, now: Timestamp) -> CustodyRow {
        CustodyRow {
            custody_id: CustodyId(id.to_owned()),
            sub: "alice".to_owned(),
            refresh_tok: b"refresh".to_vec(),
            access_tok: b"access".to_vec(),
            access_exp: now.plus_secs(3600),
            scope: None,
            status: CustodyStatus::Ok,
            next_refresh: now.plus_secs(1800),
            fail_count: 0,
            updated_at: now,
        }
    }

    /// A unique temp-file DB path per test, so tests can run concurrently
    /// without clobbering each other's file.
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "session-broker-writer-test-{tag}-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn custody_write_durability_ack_fires_only_after_commit() {
        // File-backed, not in-memory, so a *second, independent* connection
        // can observe what the writer thread committed — that's the only
        // way to prove the ack means "on disk (WAL)", not just "processed".
        let path = temp_db_path("durability");
        let _ = std::fs::remove_file(&path);
        let conn = store::open(&path, &path.with_extension("key")).unwrap();
        let writer = Writer::spawn(conn);
        let handle = writer.handle();
        let now = Timestamp(1_700_000_000);

        let outcome = handle.write_custody(CustodyWrite::Insert(custody_row("cust-1", now)));
        assert!(
            outcome.is_ok(),
            "durability ack must report success: {outcome:?}"
        );

        // The ack has returned: a brand new connection to the same file
        // must already see the row, with no retry/wait needed.
        let reader = store::open(&path, &path.with_extension("key")).unwrap();
        let loaded = repo::load_custody(&reader, &CustodyId("cust-1".to_owned())).unwrap();
        assert!(
            loaded.is_some(),
            "row must be visible to a fresh connection the instant the ack fires"
        );
        assert_eq!(loaded.unwrap().fail_count, 0);

        drop(reader);
        drop(writer);
        drop(handle);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn custody_write_to_a_missing_row_still_commits_and_acks() {
        // update_custody_* on an unknown id is a no-op UPDATE (0 rows
        // affected), not a SQL error — the ack should still be Ok. Real
        // "does this custody exist" checks belong to the caller.
        let conn = store::open_in_memory().unwrap();
        let writer = Writer::spawn(conn);
        let handle = writer.handle();
        let now = Timestamp(1_700_000_000);

        let outcome = handle.write_custody(CustodyWrite::Failure {
            custody_id: CustodyId("does-not-exist".to_owned()),
            status: CustodyStatus::Dead,
            fail_count: 9,
            next_refresh: now,
            now,
        });
        assert!(outcome.is_ok());
    }

    #[test]
    fn write_behind_session_mutation_lands_without_blocking_the_caller() {
        let path = temp_db_path("write-behind");
        let _ = std::fs::remove_file(&path);
        let conn = store::open(&path, &path.with_extension("key")).unwrap();
        let writer = Writer::spawn(conn);
        let handle = writer.handle();
        let now = Timestamp(1_700_000_000);

        // `session.custody_id` is a foreign key (foreign_keys=ON), so the
        // parent custody row must exist first. Write it through so the
        // ordering is guaranteed rather than racing the write-behind insert
        // below.
        handle
            .write_custody(CustodyWrite::Insert(custody_row("cust-1", now)))
            .unwrap();

        handle.enqueue(Command::InsertSession(SessionRow {
            sid: Sid("sid-1".to_owned()),
            custody_id: CustodyId("cust-1".to_owned()),
            sub: "alice".to_owned(),
            current_gen: 1,
            idle_exp: now.plus_secs(1000),
            absolute_exp: now.plus_secs(2000),
            status: crate::session::SessionStatus::Alive,
            created_at: now,
            meta: None,
        }));

        // `enqueue` must return immediately (it did, or this line would
        // never be reached without blocking). Force a flush by issuing a
        // durable custody write and waiting on its ack: since the writer
        // drains its whole queue into one batch per wake-up, and batches
        // apply strictly in order, waiting for *any* subsequent durable ack
        // guarantees every write-behind command enqueued before it has
        // already committed.
        let outcome = handle.write_custody(CustodyWrite::Failure {
            custody_id: CustodyId("cust-1".to_owned()),
            status: CustodyStatus::Ok,
            fail_count: 0,
            next_refresh: now.plus_secs(60),
            now: now.plus_secs(60),
        });
        assert!(outcome.is_ok());

        let reader = store::open(&path, &path.with_extension("key")).unwrap();
        let session = repo::load_session(&reader, &Sid("sid-1".to_owned())).unwrap();
        assert!(
            session.is_some(),
            "write-behind session insert must have landed"
        );

        drop(reader);
        drop(writer);
        drop(handle);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn batches_multiple_queued_commands_into_one_transaction() {
        let path = temp_db_path("batching");
        let _ = std::fs::remove_file(&path);
        let conn = store::open(&path, &path.with_extension("key")).unwrap();
        let writer = Writer::spawn(conn);
        let handle = writer.handle();
        let now = Timestamp(1_700_000_000);

        // Enqueue a burst, then a durable write last: if batching works,
        // the durable ack (which only returns after its transaction
        // commits) proves every earlier write-behind command in the same
        // wake-up committed too — a single transaction, not twenty.
        for i in 0..20u32 {
            handle.enqueue(Command::InsertTxn(TxnRow {
                txn_id: vec![i as u8; 32],
                state: format!("state-{i}"),
                nonce: "n".to_owned(),
                pkce_verifier: "v".to_owned(),
                return_to: "/".to_owned(),
                created_at: now,
            }));
        }
        let outcome = handle.write_custody(CustodyWrite::Insert(custody_row("cust-1", now)));
        assert!(outcome.is_ok());

        let reader = store::open(&path, &path.with_extension("key")).unwrap();
        let count: i64 = reader
            .query_row("SELECT COUNT(*) FROM txn", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 20,
            "every batched write-behind command must have landed"
        );

        drop(reader);
        drop(writer);
        drop(handle);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}

#[cfg(test)]
mod reaper_tests {
    use super::*;
    use crate::session::SessionStatus;
    use crate::store;

    const T0: Timestamp = Timestamp(1_700_000_000);

    /// One custody + one session + one generation, so a reap has something
    /// FK-shaped to get wrong.
    fn seed(conn: &Connection, sid: &str, custody: &str, absolute_exp: Timestamp) {
        repo::insert_custody(
            conn,
            &CustodyRow {
                custody_id: crate::session::CustodyId(custody.to_owned()),
                sub: "user-1".to_owned(),
                refresh_tok: b"r".to_vec(),
                access_tok: b"a".to_vec(),
                access_exp: T0.plus_secs(3600),
                scope: None,
                status: crate::session::CustodyStatus::Ok,
                next_refresh: T0.plus_secs(1800),
                fail_count: 0,
                updated_at: T0,
            },
        )
        .unwrap();
        repo::insert_session(
            conn,
            &SessionRow {
                sid: Sid(sid.to_owned()),
                custody_id: crate::session::CustodyId(custody.to_owned()),
                sub: "user-1".to_owned(),
                current_gen: 1,
                idle_exp: absolute_exp,
                absolute_exp,
                status: SessionStatus::Alive,
                created_at: T0,
                meta: None,
            },
        )
        .unwrap();
        repo::insert_generation(
            conn,
            &Sid(sid.to_owned()),
            1,
            &TokenHash::from_stored_bytes([sid.as_bytes()[0]; 32]),
            T0,
            absolute_exp,
        )
        .unwrap();
    }

    fn counts(conn: &Connection) -> (i64, i64, i64) {
        let s = conn
            .query_row("SELECT COUNT(*) FROM session", [], |r| r.get(0))
            .unwrap();
        let g = conn
            .query_row("SELECT COUNT(*) FROM generation", [], |r| r.get(0))
            .unwrap();
        let c = conn
            .query_row("SELECT COUNT(*) FROM custody", [], |r| r.get(0))
            .unwrap();
        (s, g, c)
    }

    /// The one that matters: a reap must never touch a live session.
    #[test]
    fn a_live_session_survives_every_sweep() {
        let conn = store::open_in_memory().unwrap();
        // Alive, ceiling far in the future.
        seed(&conn, "live", "cust-live", T0.plus_secs(30 * 86_400));

        // Sweep with a cutoff well past "now", which is the most aggressive
        // thing the scheduler could ever ask for.
        let out = repo::reap(&conn, T0.plus_secs(86_400), T0.plus_secs(86_400)).unwrap();

        assert_eq!(out.sessions, 0, "a live session must never be reaped");
        assert_eq!(out.generations, 0);
        assert_eq!(
            out.custodies, 0,
            "and its custody must not be orphan-collected out from under it"
        );
        assert_eq!(counts(&conn), (1, 1, 1));
    }

    #[test]
    fn a_tombstoned_session_is_reaped_only_once_its_window_has_passed() {
        let conn = store::open_in_memory().unwrap();
        seed(&conn, "dead", "cust-dead", T0.plus_secs(30 * 86_400));
        repo::tombstone_session(&conn, &Sid("dead".to_owned()), T0).unwrap();

        // Inside the retention window: kept, so an operator can still see it.
        let out = repo::reap(&conn, Timestamp(T0.secs() - 1), T0).unwrap();
        assert_eq!(out.sessions, 0, "still inside the window");
        assert_eq!(counts(&conn), (1, 1, 1));

        // Past it: session, its generation, and now-orphaned custody all go.
        let out = repo::reap(&conn, T0.plus_secs(1), T0).unwrap();
        assert_eq!(out.sessions, 1);
        assert_eq!(out.generations, 1);
        assert_eq!(
            out.custodies, 1,
            "an orphaned custody holds an encrypted refresh token nobody can \
             use; removing it shrinks the credential material at rest"
        );
        assert_eq!(counts(&conn), (0, 0, 0));
    }

    /// A session past its hard ceiling can never authenticate again, tombstoned
    /// or not — so it is reapable on `absolute_exp` alone.
    #[test]
    fn a_session_past_its_absolute_ceiling_is_reaped_even_while_alive() {
        let conn = store::open_in_memory().unwrap();
        seed(&conn, "expired", "cust-exp", T0);

        let out = repo::reap(&conn, T0.plus_secs(1), T0).unwrap();
        assert_eq!(out.sessions, 1);
        assert_eq!(counts(&conn), (0, 0, 0));
    }

    /// Rows tombstoned before schema v4 have no `tombstoned_at`. Unknown must
    /// mean "judge it on the ceiling", not "delete it" — guessing old on a
    /// delete path is the wrong direction to be wrong in.
    #[test]
    fn a_pre_v4_tombstone_with_no_timestamp_is_not_deleted_on_a_guess() {
        let conn = store::open_in_memory().unwrap();
        seed(&conn, "legacy", "cust-legacy", T0.plus_secs(30 * 86_400));
        conn.execute(
            "UPDATE session SET status = 'tombstoned', tombstoned_at = NULL WHERE sid = 'legacy'",
            [],
        )
        .unwrap();

        let out = repo::reap(&conn, T0.plus_secs(86_400), T0).unwrap();
        assert_eq!(
            out.sessions, 0,
            "a NULL tombstoned_at must fall through to absolute_exp, which has \
             not passed"
        );
        assert_eq!(counts(&conn).0, 1);
    }

    #[test]
    fn expired_login_transactions_are_reaped_and_fresh_ones_are_not() {
        let conn = store::open_in_memory().unwrap();
        for (id, at) in [(1u8, T0), (2u8, T0.plus_secs(1000))] {
            repo::insert_txn(
                &conn,
                &TxnRow {
                    txn_id: vec![id; 32],
                    state: "s".to_owned(),
                    nonce: "n".to_owned(),
                    pkce_verifier: "v".to_owned(),
                    return_to: "/".to_owned(),
                    created_at: at,
                },
            )
            .unwrap();
        }

        let out = repo::reap(&conn, T0, T0.plus_secs(600)).unwrap();
        assert_eq!(out.txns, 1, "only the one past INV-3's 10-minute window");
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM txn", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
    }

    /// Logout is idempotent, so a client retrying it must not be able to keep a
    /// dead row alive by pushing its death forward.
    #[test]
    fn re_tombstoning_keeps_the_first_death_not_the_latest() {
        let conn = store::open_in_memory().unwrap();
        seed(&conn, "x", "cust-x", T0.plus_secs(30 * 86_400));
        let sid = Sid("x".to_owned());
        repo::tombstone_session(&conn, &sid, T0).unwrap();
        repo::tombstone_session(&conn, &sid, T0.plus_secs(10_000)).unwrap();

        let at: i64 = conn
            .query_row(
                "SELECT tombstoned_at FROM session WHERE sid = 'x'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(at, T0.secs(), "the first death is the real one");
    }

    #[test]
    fn reaping_an_empty_store_is_a_no_op_not_an_error() {
        let conn = store::open_in_memory().unwrap();
        let out = repo::reap(&conn, T0, T0).unwrap();
        assert!(out.is_empty());
    }
}
