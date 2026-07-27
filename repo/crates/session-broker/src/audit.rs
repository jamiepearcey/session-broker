//! The audit record: what happened, who did it, and a guarantee that the row
//! and the thing it records cannot disagree (ADR-0015).
//!
//! ## Not a log stream
//!
//! Audit rows live in the broker's own SQLite store, not in the log pipeline.
//! A record whose completeness is a function of a sidecar's configuration
//! cannot answer "prove nobody issued a key that week". Rows are *also* emitted
//! to `broker::audit` at `info` (fail-open) so a collector gets the long-term
//! archive — the store keeps a bounded, queryable window.
//!
//! ## Two tiers, drawn at power
//!
//! * **Tier A (transactional, fail-closed).** The row is carried inside the same
//!   writer command as the state change and applied in the same SQLite
//!   transaction. There is no reachable state with the change but not the row,
//!   or the row but not the change. Reserved for events that move power:
//!   issuing or revoking a credential, forcing a user out, changing how loud the
//!   diagnostics are.
//! * **Tier B (batched, fail-open, depth-bounded).** Everything else with audit
//!   value. Enqueued and forgotten. At the queue bound events are dropped, the
//!   drop is counted, and the next accepted event carries an `audit.gap` row
//!   saying how many were lost. **A record that is incomplete says so** — a
//!   silently short record is the failure this exists to prevent.
//!
//! ## Nothing on the hot path writes a row
//!
//! `/session/refresh` (INV-8) and `/authz` produce metrics only, success and
//! refusal alike. That is not a shortcut for speed: a request that changed
//! nothing is not history, and recording ten thousand identical "yes" answers
//! destroys the signal-to-noise of the record an investigator actually reads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::clock::Timestamp;
use crate::store::repo::AuditRow;
use crate::store::writer::{Command, WriterHandle};
use crate::telemetry::metrics::Metrics;

/// Stable dotted action names. Renaming one breaks whatever is alerting on it;
/// adding one is additive. The catalogue with meanings is in
/// `docs/architecture/observability.md` §4.
pub mod action {
    // Tier A — transactional, fail-closed.
    pub const KEY_ISSUED: &str = "key.issued";
    pub const KEY_REVOKED: &str = "key.revoked";
    pub const SESSION_REVOKED: &str = "session.revoked";
    pub const LOGGING_LEVEL_CHANGED: &str = "logging.level_changed";

    // Tier B — batched, fail-open.
    pub const SESSION_CREATED: &str = "session.created";
    pub const SESSION_LOGGED_OUT: &str = "session.logged_out";
    pub const LOGIN_FAILED: &str = "login.failed";
    pub const TOKEN_EXCHANGED: &str = "token.exchanged";
    pub const TOKEN_REFUSED: &str = "token.refused";
    pub const CUSTODY_DEGRADED: &str = "custody.degraded";
    pub const CUSTODY_DEAD: &str = "custody.dead";
    pub const CUSTODY_REVOKED_UPSTREAM: &str = "custody.revoked_upstream";
    pub const SESSION_ANOMALY: &str = "session.anomaly";
    pub const AUDIT_GAP: &str = "audit.gap";
}

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    /// Someone holding the admin key.
    Admin,
    /// A service holding an issued API key.
    Backend,
    /// The signed-in person themselves.
    User,
    /// The broker's own background work — the keepalive worker, the pruner.
    System,
    /// Nobody identifiable. Failed logins land here, and are recorded anyway.
    Anonymous,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::Admin => "admin",
            ActorKind::Backend => "backend",
            ActorKind::User => "user",
            ActorKind::System => "system",
            ActorKind::Anonymous => "anonymous",
        }
    }

    pub fn from_str_lossy(s: &str) -> ActorKind {
        match s {
            "admin" => ActorKind::Admin,
            "backend" => ActorKind::Backend,
            "user" => ActorKind::User,
            "system" => ActorKind::System,
            _ => ActorKind::Anonymous,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        }
    }
}

/// Builder for an [`AuditRow`].
///
/// Deliberately has no method that takes token material. The redaction rule
/// (INV-12) is easier to keep when the type system offers no place to put a
/// secret: `detail` is the only free-form field, it is JSON, and it is
/// documented as non-secret.
#[derive(Debug, Clone)]
pub struct Event {
    row: AuditRow,
}

impl Event {
    pub fn new(action: &str, outcome: Outcome, actor_kind: ActorKind, at: Timestamp) -> Event {
        Event {
            row: AuditRow {
                at,
                action: action.to_owned(),
                outcome: outcome.as_str().to_owned(),
                actor_kind: actor_kind.as_str().to_owned(),
                actor_id: None,
                subject: None,
                sid: None,
                custody_id: None,
                key_id: None,
                reason: None,
                client_ip_prefix: None,
                detail: None,
            },
        }
    }

    pub fn actor_id(mut self, id: impl Into<String>) -> Event {
        self.row.actor_id = Some(id.into());
        self
    }

    /// Whose data was acted on.
    pub fn subject(mut self, sub: impl Into<String>) -> Event {
        self.row.subject = Some(sub.into());
        self
    }

    pub fn sid(mut self, sid: impl Into<String>) -> Event {
        self.row.sid = Some(sid.into());
        self
    }

    pub fn custody_id(mut self, id: impl Into<String>) -> Event {
        self.row.custody_id = Some(id.into());
        self
    }

    pub fn key_id(mut self, id: impl Into<String>) -> Event {
        self.row.key_id = Some(id.into());
        self
    }

    /// The refusal code, on failure. The same string the caller was given, so
    /// the record and the client agree about what happened.
    pub fn reason(mut self, reason: impl Into<String>) -> Event {
        self.row.reason = Some(reason.into());
        self
    }

    /// A **/24 or /48 prefix** (see [`crate::telemetry::ip_prefix`]), never a
    /// full address.
    pub fn client_ip_prefix(mut self, prefix: impl Into<String>) -> Event {
        self.row.client_ip_prefix = Some(prefix.into());
        self
    }

    /// Non-secret structured context.
    pub fn detail(mut self, detail: serde_json::Value) -> Event {
        self.row.detail = Some(detail.to_string());
        self
    }

    pub fn into_row(self) -> AuditRow {
        self.row
    }
}

/// How subjects are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectMode {
    /// The subject as the IdP gave it.
    Plain,
    /// A stable truncated SHA-256. Still correlatable across rows, no longer
    /// naming people — for deployments retaining audit under a data-minimisation
    /// regime.
    Hashed,
}

impl SubjectMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectMode::Plain => "plain",
            SubjectMode::Hashed => "hashed",
        }
    }
}

impl std::str::FromStr for SubjectMode {
    type Err = String;

    fn from_str(s: &str) -> Result<SubjectMode, String> {
        match s.to_ascii_lowercase().as_str() {
            "plain" => Ok(SubjectMode::Plain),
            "hashed" | "pseudonymous" => Ok(SubjectMode::Hashed),
            other => Err(format!("must be \"plain\" or \"hashed\", got {other:?}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub retention_days: u32,
    pub queue_capacity: usize,
    /// Window in which repeated `token.exchanged` for the same `(key_id, sid)`
    /// collapse to one row.
    pub coalesce_secs: u64,
    pub record_rotations: bool,
    pub subject_mode: SubjectMode,
}

impl Default for AuditConfig {
    fn default() -> AuditConfig {
        AuditConfig {
            retention_days: 90,
            queue_capacity: 8_192,
            coalesce_secs: 300,
            record_rotations: false,
            subject_mode: SubjectMode::Plain,
        }
    }
}

/// The handle every emitting site holds. Cheap to clone.
#[derive(Clone)]
pub struct AuditSink {
    inner: Arc<Inner>,
}

struct Inner {
    writer: WriterHandle,
    metrics: Arc<Metrics>,
    config: AuditConfig,
    /// Tier-B events enqueued and not yet applied by the writer. The bound this
    /// is compared against is what stops a stalled writer thread from becoming
    /// unbounded memory growth inside the credential custodian.
    depth: Arc<AtomicI64>,
    /// Dropped since the last `audit.gap` row was emitted.
    pending_gap: AtomicU64,
    /// `(key_id, sid) -> last recorded`. Bounded by eviction on write; see
    /// [`Inner::should_record_exchange`].
    exchange_seen: Mutex<HashMap<(String, String), i64>>,
}

/// Upper bound on the coalescing map. Past this it is cleared wholesale rather
/// than evicted one by one: the map is an optimisation over an already-correct
/// "record everything" behaviour, so losing it costs at most one redundant row
/// per pair, and an unbounded map inside the audit path would be its own
/// incident.
const EXCHANGE_MAP_MAX: usize = 8_192;

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSink")
            .field("depth", &self.depth())
            .field("retention_days", &self.inner.config.retention_days)
            .finish()
    }
}

impl AuditSink {
    pub fn new(writer: WriterHandle, metrics: Arc<Metrics>, config: AuditConfig) -> AuditSink {
        AuditSink {
            inner: Arc::new(Inner {
                writer,
                metrics,
                config,
                depth: Arc::new(AtomicI64::new(0)),
                pending_gap: AtomicU64::new(0),
                exchange_seen: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn config(&self) -> &AuditConfig {
        &self.inner.config
    }

    pub fn depth(&self) -> i64 {
        self.inner.depth.load(Ordering::Relaxed)
    }

    /// Tier B: enqueue and return. Never blocks, never fails the caller.
    pub fn record(&self, event: Event) {
        let mut row = event.into_row();
        self.pseudonymise(&mut row);
        self.emit_to_log(&row, "tier_b");

        let depth = self.inner.depth.load(Ordering::Relaxed);
        if depth >= self.inner.config.queue_capacity as i64 {
            // Drop, but count it. The next accepted event carries the gap.
            self.inner.pending_gap.fetch_add(1, Ordering::Relaxed);
            self.inner.metrics.record_audit_dropped(1);
            self.inner.metrics.set_audit_queue_depth(depth);
            return;
        }

        // If the queue has drained since a drop, say so before anything else.
        let dropped = self.inner.pending_gap.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let gap = Event::new(
                action::AUDIT_GAP,
                Outcome::Failure,
                ActorKind::System,
                row.at,
            )
            .reason("queue_full")
            .detail(serde_json::json!({ "dropped": dropped }))
            .into_row();
            tracing::error!(
                target: "broker::audit",
                dropped,
                "audit queue overflowed; the record has a hole and says so"
            );
            self.enqueue(gap);
        }

        self.enqueue(row);
    }

    /// Tier A: hand the row to the caller so it can be applied in the same
    /// transaction as the state change it records.
    ///
    /// Returns the row rather than writing it, because the guarantee is not
    /// "written promptly" — it is "written *with* the change, or neither". Only
    /// [`crate::store::writer`] can offer that, so only it may write these.
    pub fn transactional(&self, event: Event) -> AuditRow {
        let mut row = event.into_row();
        self.pseudonymise(&mut row);
        self.emit_to_log(&row, "tier_a");
        self.inner.metrics.record_audit("tier_a");
        row
    }

    /// A Tier-A write failed, so the operation it accompanied was refused.
    pub fn note_transactional_failure(&self) {
        self.inner.metrics.record_audit_failed();
    }

    /// Should this `/internal/token` exchange be recorded, or has an equivalent
    /// one been recorded recently?
    ///
    /// The audit fact is "backend `envoy-edge` acted for `user-1` this
    /// afternoon", not the ten thousand times it did so. Refusals never come
    /// here — a refusal is always interesting.
    pub fn should_record_exchange(&self, key_id: &str, sid: &str, now: Timestamp) -> bool {
        let window = self.inner.config.coalesce_secs as i64;
        if window <= 0 {
            return true;
        }
        let mut seen = match self.inner.exchange_seen.lock() {
            Ok(guard) => guard,
            // A poisoned mutex here means a previous holder panicked. Recording
            // an extra row is strictly safer than skipping one.
            Err(_) => return true,
        };
        let key = (key_id.to_owned(), sid.to_owned());
        if let Some(last) = seen.get(&key) {
            if now.secs() - *last < window {
                return false;
            }
        }
        if seen.len() >= EXCHANGE_MAP_MAX {
            seen.clear();
        }
        seen.insert(key, now.secs());
        true
    }

    /// Ask the writer to drop rows older than the retention window. `0` days
    /// disables pruning entirely, which is a deliberate choice an operator has
    /// to make rather than a default they inherit.
    pub fn prune(&self, now: Timestamp) {
        let days = self.inner.config.retention_days;
        if days == 0 {
            return;
        }
        let cutoff = Timestamp(now.secs() - (days as i64) * 86_400);
        self.inner.writer.enqueue(Command::PruneAudit(cutoff));
    }

    /// Called by the writer once a Tier-B row has been applied.
    pub fn queue_depth_handle(&self) -> Arc<AtomicI64> {
        self.inner.depth.clone()
    }

    fn enqueue(&self, row: AuditRow) {
        self.inner.depth.fetch_add(1, Ordering::Relaxed);
        self.inner
            .metrics
            .set_audit_queue_depth(self.inner.depth.load(Ordering::Relaxed));
        self.inner.metrics.record_audit("tier_b");
        self.inner.writer.enqueue(Command::Audit {
            row: Box::new(row),
            depth: self.inner.depth.clone(),
        });
    }

    fn pseudonymise(&self, row: &mut AuditRow) {
        if self.inner.config.subject_mode != SubjectMode::Hashed {
            return;
        }
        row.subject = row.subject.as_deref().map(pseudonym);
        // Only user-shaped actors are people. A `key_id` is a credential's name
        // and hashing it would make the record unreadable without protecting
        // anyone.
        if row.actor_kind == "user" {
            row.actor_id = row.actor_id.as_deref().map(pseudonym);
        }
    }

    /// The fail-open half of ADR-0014: every audit event is also a log line, so
    /// a collector holds the long-term archive.
    fn emit_to_log(&self, row: &AuditRow, tier: &str) {
        tracing::info!(
            target: "broker::audit",
            tier,
            action = %row.action,
            outcome = %row.outcome,
            actor_kind = %row.actor_kind,
            actor_id = row.actor_id.as_deref().unwrap_or("-"),
            subject = row.subject.as_deref().unwrap_or("-"),
            sid = row.sid.as_deref().unwrap_or("-"),
            key_id = row.key_id.as_deref().unwrap_or("-"),
            custody_id = row.custody_id.as_deref().unwrap_or("-"),
            reason = row.reason.as_deref().unwrap_or("-"),
            "audit"
        );
    }
}

/// Stable, non-reversible, and correlatable — which is the whole requirement.
/// Truncated to 128 bits: collision-implausible at any realistic subject count,
/// and half the width in every row and every console cell.
fn pseudonym(value: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"session-broker/audit-subject/v1");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
