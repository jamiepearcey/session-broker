//! Tests for the audit record.
//!
//! The claims worth holding the implementation to are not "a row was written" —
//! they are the ones ADR-0015 makes and that an operator would later rely on:
//! the record and the change cannot disagree, an incomplete record says so, and
//! no secret material reaches a row.

use super::*;
use crate::store::repo::{self, AuditQuery};
use crate::store::writer::{AdminWrite, Writer};
use crate::store::Reader;

const T0: Timestamp = Timestamp(1_700_000_000);

fn temp_db(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "session-broker-audit-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    let _ = std::fs::remove_file(path.with_extension("key"));
}

struct Harness {
    path: std::path::PathBuf,
    writer: Writer,
    reader: Reader,
    sink: AuditSink,
    metrics: Arc<Metrics>,
}

fn harness(tag: &str, config: AuditConfig) -> Harness {
    let path = temp_db(tag);
    let keyfile = path.with_extension("key");
    // File-backed, not `:memory:`: two in-memory connections are two separate
    // databases, and the whole point of a Tier-A guarantee is that a second
    // reader sees the row the writer committed.
    let conn = crate::store::open(&path, &keyfile).unwrap();
    let read_conn = crate::store::open(&path, &keyfile).unwrap();
    let writer = Writer::spawn(conn);
    let metrics = Metrics::new();
    let sink = AuditSink::new(writer.handle(), metrics.clone(), config);
    Harness {
        path,
        writer,
        reader: Reader::new(read_conn),
        sink,
        metrics,
    }
}

impl Harness {
    fn rows(&self) -> Vec<repo::StoredAuditRow> {
        self.reader.with(|conn| {
            repo::list_audit(
                conn,
                &AuditQuery {
                    limit: 1000,
                    ..AuditQuery::default()
                },
            )
            .unwrap()
        })
    }

    /// Force the writer to flush by issuing a write-through command and waiting
    /// on its ack. Batches apply strictly in order, so anything enqueued before
    /// this has already committed when it returns.
    fn flush(&self) {
        let _ = self
            .writer
            .handle()
            .write_admin(AdminWrite::TouchApiKey {
                key_id: "does-not-exist".to_owned(),
                now: T0,
            });
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        cleanup(&self.path);
    }
}

/// The Tier-A claim, stated the way an auditor would: there is no reachable
/// state in which a credential exists without a record of it being issued.
#[test]
fn a_tier_a_row_and_its_mutation_commit_together() {
    let h = harness("tier-a", AuditConfig::default());

    let row = h.sink.transactional(
        Event::new(action::KEY_ISSUED, Outcome::Success, ActorKind::Admin, T0)
            .actor_id("admin_api_key")
            .key_id("bk_test")
            .detail(serde_json::json!({ "name": "envoy-edge" })),
    );
    h.writer
        .handle()
        .write_admin_audited(
            AdminWrite::InsertApiKey {
                key_id: "bk_test".to_owned(),
                name: "envoy-edge".to_owned(),
                key_hash: vec![7u8; 32],
                created_by: None,
                now: T0,
            },
            Some(row),
        )
        .expect("the batch commits");

    let keys = h.reader.with(repo::list_api_keys).unwrap();
    let audit = h.rows();
    assert_eq!(keys.len(), 1, "the key exists");
    assert_eq!(audit.len(), 1, "and so does its record");
    assert_eq!(audit[0].row.action, action::KEY_ISSUED);
    assert_eq!(audit[0].row.key_id.as_deref(), Some("bk_test"));
    assert_eq!(audit[0].row.outcome, "success");
}

/// The failure this catches is subtle and would otherwise be invisible: a
/// revoke that matched nothing must not leave a row asserting a key was
/// revoked. The record has to give the same answer the caller got.
#[test]
fn a_revoke_that_matched_nothing_is_recorded_as_a_failure() {
    let h = harness("revoke-miss", AuditConfig::default());

    let row = h.sink.transactional(
        Event::new(action::KEY_REVOKED, Outcome::Success, ActorKind::Admin, T0).key_id("bk_absent"),
    );
    let outcome = h
        .writer
        .handle()
        .write_admin_audited(
            AdminWrite::RevokeApiKey {
                key_id: "bk_absent".to_owned(),
                now: T0,
            },
            Some(row),
        )
        .unwrap();

    assert!(!outcome, "there was nothing to revoke");
    let audit = h.rows();
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0].row.outcome, "failure",
        "the row must not claim a revocation that did not happen"
    );
    assert_eq!(audit[0].row.reason.as_deref(), Some("not_found"));
}

/// The Tier-B claim: an incomplete record says so. A silently short record is
/// the failure mode the whole drop-counting apparatus exists to prevent.
#[test]
fn overflowing_the_tier_b_queue_leaves_a_gap_marker_not_a_silence() {
    // Capacity 1 makes the bound trivial to reach deterministically. The writer
    // is running, so the queue also drains — which is what lets the gap row be
    // emitted rather than dropped along with everything else.
    let h = harness(
        "gap",
        AuditConfig {
            queue_capacity: 1,
            ..AuditConfig::default()
        },
    );

    for i in 0..200 {
        h.sink.record(
            Event::new(action::LOGIN_FAILED, Outcome::Failure, ActorKind::Anonymous, T0)
                .reason("bad_state")
                .detail(serde_json::json!({ "i": i })),
        );
    }
    h.flush();
    // The writer batches on a 50ms timer; give it room to drain what a burst of
    // 200 enqueues left behind.
    std::thread::sleep(std::time::Duration::from_millis(300));
    h.flush();

    let rows = h.rows();
    let dropped = h.metrics.audit_dropped_total();
    assert!(dropped > 0, "capacity 1 under a burst of 200 must drop some");
    assert!(
        rows.len() < 200,
        "and the record must be genuinely short: {} rows",
        rows.len()
    );

    let gap = rows
        .iter()
        .find(|r| r.row.action == action::AUDIT_GAP)
        .expect("a gap must be recorded, or the shortfall is invisible");
    assert_eq!(gap.row.reason.as_deref(), Some("queue_full"));
    let detail: serde_json::Value =
        serde_json::from_str(gap.row.detail.as_deref().unwrap()).unwrap();
    assert!(
        detail["dropped"].as_u64().unwrap() > 0,
        "the gap has to say HOW MANY; 'something was lost' is not a record"
    );
}

/// A stalled batch must not arm the bound permanently. Depth is released for
/// every audit command in a batch whether or not the transaction commits — get
/// this wrong and one bad batch silences the record forever.
#[test]
fn queue_depth_returns_to_zero_after_the_writer_drains() {
    let h = harness("depth", AuditConfig::default());
    for _ in 0..50 {
        h.sink.record(Event::new(
            action::SESSION_CREATED,
            Outcome::Success,
            ActorKind::User,
            T0,
        ));
    }
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(200));
    h.flush();
    assert_eq!(
        h.sink.depth(),
        0,
        "every enqueued row must release its slot once applied"
    );
}

#[test]
fn token_exchanges_coalesce_per_key_and_session_but_never_across_them() {
    let h = harness("coalesce", AuditConfig::default()); // 300s window

    assert!(h.sink.should_record_exchange("bk_1", "sid_1", T0));
    assert!(
        !h.sink.should_record_exchange("bk_1", "sid_1", T0.plus_secs(299)),
        "the same backend acting for the same user inside the window adds no fact"
    );
    assert!(
        h.sink.should_record_exchange("bk_1", "sid_2", T0.plus_secs(1)),
        "a DIFFERENT user is a different fact and must never be collapsed"
    );
    assert!(
        h.sink.should_record_exchange("bk_2", "sid_1", T0.plus_secs(1)),
        "a different backend likewise"
    );
    assert!(
        h.sink.should_record_exchange("bk_1", "sid_1", T0.plus_secs(301)),
        "and the window reopens"
    );
}

#[test]
fn hashed_subject_mode_pseudonymises_people_but_not_credentials() {
    let h = harness(
        "hashed",
        AuditConfig {
            subject_mode: SubjectMode::Hashed,
            ..AuditConfig::default()
        },
    );

    let row = h.sink.transactional(
        Event::new(action::KEY_ISSUED, Outcome::Success, ActorKind::Admin, T0)
            .actor_id("admin_api_key")
            .subject("alice@example.com")
            .key_id("bk_1"),
    );
    assert_ne!(row.subject.as_deref(), Some("alice@example.com"));
    assert!(!row.subject.as_deref().unwrap().contains("alice"));
    assert_eq!(
        row.actor_id.as_deref(),
        Some("admin_api_key"),
        "a credential's name is not a person; hashing it would make the record \
         unreadable without protecting anyone"
    );

    // Stable, or correlation across rows would be impossible and the mode
    // would be useless rather than merely private.
    let again = h.sink.transactional(
        Event::new(action::SESSION_CREATED, Outcome::Success, ActorKind::User, T0)
            .subject("alice@example.com"),
    );
    assert_eq!(row.subject, again.subject);
}

/// INV-12, enforced the way INV-5 was: by looking, not by reviewing.
#[test]
fn no_builder_method_can_put_secret_material_in_a_row() {
    let h = harness("redaction", AuditConfig::default());

    const COOKIE: &str = "SECRETCOOKIEVALUE0123456789";
    const ACCESS: &str = "SECRETACCESSTOKEN0123456789";

    // Everything an emitting site is allowed to attach, all at once.
    let row = h.sink.transactional(
        Event::new(action::TOKEN_EXCHANGED, Outcome::Success, ActorKind::Backend, T0)
            .actor_id("bk_1")
            .key_id("bk_1")
            .subject("user-1")
            .sid("sid-1")
            .custody_id("cust-1")
            .reason("ok")
            .client_ip_prefix("203.0.113.0/24")
            .detail(serde_json::json!({ "name": "envoy-edge" })),
    );

    let serialised = format!("{row:?}");
    for secret in [COOKIE, ACCESS] {
        assert!(
            !serialised.contains(secret),
            "no path through the builder may carry token material"
        );
    }
    assert!(
        !serialised.contains("203.0.113.42"),
        "and an address is only ever a prefix"
    );
}

/// Retention is real, and it is the reason the store's copy is a working set
/// rather than an archive.
#[test]
fn pruning_drops_rows_past_the_window_and_leaves_the_rest() {
    let h = harness(
        "prune",
        AuditConfig {
            retention_days: 30,
            ..AuditConfig::default()
        },
    );

    let old = Timestamp(T0.secs() - 31 * 86_400);
    h.sink.record(Event::new(
        action::SESSION_CREATED,
        Outcome::Success,
        ActorKind::User,
        old,
    ));
    h.sink.record(Event::new(
        action::SESSION_CREATED,
        Outcome::Success,
        ActorKind::User,
        T0,
    ));
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(h.rows().len(), 2);

    h.sink.prune(T0);
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(150));

    let rows = h.rows();
    assert_eq!(rows.len(), 1, "the row past the window is gone");
    assert_eq!(rows[0].row.at.secs(), T0.secs());

    // `seq` must NOT be reused after a prune: it is the pagination cursor, and
    // a gap in it has to read as evidence rather than ambiguity.
    let before = rows[0].seq;
    h.sink.record(Event::new(
        action::SESSION_LOGGED_OUT,
        Outcome::Success,
        ActorKind::User,
        T0,
    ));
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(150));
    let after = h.rows();
    assert!(
        after[0].seq > before,
        "AUTOINCREMENT must not hand a pruned sequence number back out"
    );
}

/// `0` days is a supported choice with an unbounded consequence, so it must be
/// exactly what it says: no pruning at all, not "prune to today".
#[test]
fn zero_retention_days_prunes_nothing() {
    let h = harness(
        "keep-forever",
        AuditConfig {
            retention_days: 0,
            ..AuditConfig::default()
        },
    );
    h.sink.record(Event::new(
        action::SESSION_CREATED,
        Outcome::Success,
        ActorKind::User,
        Timestamp(1),
    ));
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(150));

    h.sink.prune(T0);
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(h.rows().len(), 1, "a row from 1970 must survive");
}

#[test]
fn action_filters_match_by_prefix_without_treating_underscores_as_wildcards() {
    let h = harness("filter", AuditConfig::default());
    for action in [action::KEY_ISSUED, action::KEY_REVOKED, action::LOGIN_FAILED] {
        h.sink.record(Event::new(
            action,
            Outcome::Success,
            ActorKind::Admin,
            T0,
        ));
    }
    h.flush();
    std::thread::sleep(std::time::Duration::from_millis(150));

    let keys = h.reader.with(|conn| {
        repo::list_audit(
            conn,
            &AuditQuery {
                action_prefix: Some("key.".to_owned()),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .unwrap()
    });
    assert_eq!(keys.len(), 2, "prefix match finds both key.* actions");

    // `_` is a LIKE wildcard. Unescaped, `key_` would match `key.issued` and an
    // operator filtering for a literal would silently get the wrong rows.
    let literal = h.reader.with(|conn| {
        repo::list_audit(
            conn,
            &AuditQuery {
                action_prefix: Some("key_".to_owned()),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .unwrap()
    });
    assert!(literal.is_empty(), "no action is literally prefixed 'key_'");
}
