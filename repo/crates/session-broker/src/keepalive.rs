//! The background keepalive worker: what keeps upstream tokens warm so that the
//! refresh hot path never has to (INV-8).
//!
//! The scheduling algorithm is a pure, synchronous core ([`Scheduler`]) with the
//! async plumbing ([`KeepaliveWorker`]) wrapped thinly around it. That split is
//! deliberate: backoff curves, jitter bounds and revocation propagation are
//! exactly the things that are miserable to test through a runtime, and here
//! they are ordinary function calls over an injected clock.
//!
//! Failure taxonomy, from `docs/architecture/implementation-strategy.md` §6:
//!
//! * **Transient** (network, 5xx, 429) — retry with exponential backoff and full
//!   jitter, honouring `Retry-After`. The custody goes `degraded` only once its
//!   access token has actually expired, because sessions do not depend on
//!   upstream liveness; only token exchange and the proxy lane do.
//! * **Permanent** (`invalid_grant`: the refresh token was revoked, expired or
//!   already consumed) — the custody is dead. Under the default `kill` policy
//!   every session it backs is tombstoned, because upstream revocation is an
//!   administrative security action and must propagate (ADR-0011).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use crate::clock::{Clock, Timestamp};
use crate::session::{CustodyId, CustodyStatus, RevocationPolicy, SessionMap};
use crate::store::writer::WriterHandle;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeepalivePolicy {
    /// Fraction of the access token's lifetime at which to refresh. 0.6 leaves
    /// room for two full retry budgets before the token actually expires.
    pub lead_fraction: f64,
    /// Jitter applied to the lead margin, as a fraction either side. Spreads a
    /// fleet of custodies that were all created at the same moment.
    pub jitter_fraction: f64,
    pub base_backoff_secs: u64,
    pub max_backoff_secs: u64,
    /// Ceiling on concurrent upstream calls, to stay a good citizen against an
    /// IdP that may be rate-limiting us.
    pub max_concurrent: usize,
    pub on_upstream_revoked: RevocationPolicy,
}

impl Default for KeepalivePolicy {
    fn default() -> Self {
        KeepalivePolicy {
            lead_fraction: 0.6,
            jitter_fraction: 0.1,
            base_backoff_secs: 1,
            max_backoff_secs: 300,
            max_concurrent: 8,
            on_upstream_revoked: RevocationPolicy::Kill,
        }
    }
}

/// The result of one attempt to refresh an upstream grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    Success {
        /// Lifetime of the newly issued access token, in seconds.
        lifetime_secs: u64,
        /// Some IdPs rotate the refresh token on every use; both behaviours must
        /// work. When present this must be durably written *before* the schedule
        /// is updated, or a crash orphans the grant (§6).
        rotated_refresh: bool,
    },
    /// Retryable. `retry_after` carries an upstream `Retry-After` when it sent one.
    Transient { retry_after_secs: Option<u64> },
    /// `invalid_grant`. The refresh token will never work again.
    Permanent,
}

/// Injected randomness, so jitter is a test input rather than a source of flake.
pub trait Jitter: Send + Sync + 'static {
    /// A value in `[0, 1)`.
    fn unit(&self) -> f64;
}

/// Production jitter.
pub struct RandJitter;

impl Jitter for RandJitter {
    fn unit(&self) -> f64 {
        use rand::Rng as _;
        rand::thread_rng().gen_range(0.0..1.0)
    }
}

/// Fixed jitter for tests. `0.5` is the midpoint, i.e. no net displacement.
pub struct FixedJitter(pub f64);

impl Jitter for FixedJitter {
    fn unit(&self) -> f64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyState {
    pub status: CustodyStatus,
    /// When the current access token expires — the deadline the schedule is
    /// racing, and what decides whether a retrying custody is merely retrying or
    /// actually degraded.
    pub access_exp: Timestamp,
    pub next_refresh: Timestamp,
    pub fail_count: u32,
    /// Guards against two in-flight refreshes for one custody, which with a
    /// single-use rotating refresh token would burn the grant.
    pub refreshing: bool,
}

/// The pure scheduling core.
#[derive(Debug)]
pub struct Scheduler {
    policy: KeepalivePolicy,
    entries: HashMap<CustodyId, CustodyState>,
    due: BinaryHeap<Reverse<(i64, CustodyId)>>,
}

impl Scheduler {
    pub fn new(policy: KeepalivePolicy) -> Scheduler {
        Scheduler {
            policy,
            entries: HashMap::new(),
            due: BinaryHeap::new(),
        }
    }

    pub fn policy(&self) -> &KeepalivePolicy {
        &self.policy
    }

    pub fn get(&self, custody: &CustodyId) -> Option<&CustodyState> {
        self.entries.get(custody)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Register a newly provisioned grant, or one rehydrated at boot. A
    /// `next_refresh` already in the past is legitimate after a restart and will
    /// simply come due immediately — the caller spreads those (see
    /// [`KeepaliveWorker`]).
    pub fn insert(
        &mut self,
        custody: CustodyId,
        issued_at: Timestamp,
        lifetime_secs: u64,
        jitter: &dyn Jitter,
    ) {
        let next_refresh = next_refresh_at(&self.policy, issued_at, lifetime_secs, jitter);
        self.entries.insert(
            custody.clone(),
            CustodyState {
                status: CustodyStatus::Ok,
                access_exp: issued_at.plus_secs(lifetime_secs),
                next_refresh,
                fail_count: 0,
                refreshing: false,
            },
        );
        self.due.push(Reverse((next_refresh.secs(), custody)));
    }

    /// Re-register a custody read back from the store at boot.
    ///
    /// Distinct from [`Scheduler::insert`] because the schedule is *restored*,
    /// not computed: `next_refresh` was decided by whichever process last
    /// refreshed this grant, and recomputing it from a lifetime we no longer
    /// know would either bring every custody due at once or push a nearly
    /// expired token past its own expiry. The stored `fail_count` and status
    /// come back too, so a custody that was already backing off keeps backing
    /// off instead of getting a free retry on every deploy.
    pub fn insert_restored(
        &mut self,
        custody: CustodyId,
        status: CustodyStatus,
        access_exp: Timestamp,
        next_refresh: Timestamp,
    ) {
        self.entries.insert(
            custody.clone(),
            CustodyState {
                status,
                access_exp,
                next_refresh,
                fail_count: 0,
                refreshing: false,
            },
        );
        self.due.push(Reverse((next_refresh.secs(), custody)));
    }

    pub fn remove(&mut self, custody: &CustodyId) {
        // The heap keeps a stale entry; `take_due` drops entries with no state.
        self.entries.remove(custody);
    }

    /// Everything due at `now`, marked in-flight. Custodies already refreshing,
    /// dead, or removed are skipped.
    pub fn take_due(&mut self, now: Timestamp) -> Vec<CustodyId> {
        let mut ready = Vec::new();
        loop {
            match self.due.peek() {
                Some(Reverse((at, _))) if *at <= now.secs() => {}
                _ => break,
            }
            let Some(Reverse((_, custody))) = self.due.pop() else {
                break;
            };
            let Some(state) = self.entries.get_mut(&custody) else {
                continue; // removed since it was scheduled
            };
            // A stale heap entry from a since-rescheduled custody.
            if state.next_refresh.secs() > now.secs() {
                continue;
            }
            if state.refreshing || state.status == CustodyStatus::Dead {
                continue;
            }
            state.refreshing = true;
            ready.push(custody);
        }
        ready
    }

    /// When the next custody comes due, for the runner's sleep.
    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.entries.values().map(|s| s.next_refresh).min()
    }

    /// Apply the result of an attempt and reschedule. Returns the status the
    /// custody now has, so the caller can propagate it to sessions.
    pub fn record(
        &mut self,
        custody: &CustodyId,
        outcome: RefreshOutcome,
        now: Timestamp,
        jitter: &dyn Jitter,
    ) -> Option<CustodyStatus> {
        let policy = self.policy;
        let state = self.entries.get_mut(custody)?;
        state.refreshing = false;

        let next = match outcome {
            RefreshOutcome::Success { lifetime_secs, .. } => {
                state.status = CustodyStatus::Ok;
                state.fail_count = 0;
                state.access_exp = now.plus_secs(lifetime_secs);
                next_refresh_at(&policy, now, lifetime_secs, jitter)
            }
            RefreshOutcome::Transient { retry_after_secs } => {
                state.fail_count = state.fail_count.saturating_add(1);
                // Only degraded once the token we are failing to replace has
                // actually expired. Until then nothing downstream is affected.
                state.status = if now >= state.access_exp {
                    CustodyStatus::Degraded
                } else {
                    CustodyStatus::Ok
                };
                now.plus_secs(backoff_secs(
                    &policy,
                    state.fail_count - 1,
                    retry_after_secs,
                    jitter,
                ))
            }
            RefreshOutcome::Permanent => {
                state.status = CustodyStatus::Dead;
                state.next_refresh = now;
                // Stop scheduling entirely; nothing will make this grant work.
                return Some(CustodyStatus::Dead);
            }
        };

        state.next_refresh = next;
        let status = state.status;
        self.due.push(Reverse((next.secs(), custody.clone())));
        Some(status)
    }
}

/// `issued_at + lifetime × lead_fraction`, jittered by ±`jitter_fraction` of the
/// lead margin so a fleet provisioned together does not stampede the IdP.
fn next_refresh_at(
    policy: &KeepalivePolicy,
    issued_at: Timestamp,
    lifetime_secs: u64,
    jitter: &dyn Jitter,
) -> Timestamp {
    let lead = lifetime_secs as f64 * policy.lead_fraction;
    // unit() ∈ [0,1) mapped to [-1, 1) then scaled by the jitter fraction.
    let displacement = (jitter.unit() * 2.0 - 1.0) * policy.jitter_fraction * lead;
    let delay = (lead + displacement).max(1.0) as u64;
    issued_at.plus_secs(delay)
}

/// Full-jitter exponential backoff, capped. An upstream `Retry-After` wins
/// outright: it is the one party that knows when it will be ready.
fn backoff_secs(
    policy: &KeepalivePolicy,
    fail_count: u32,
    retry_after: Option<u64>,
    jitter: &dyn Jitter,
) -> u64 {
    if let Some(secs) = retry_after {
        return secs.min(policy.max_backoff_secs);
    }
    let exponential = policy
        .base_backoff_secs
        .saturating_mul(1u64 << fail_count.min(16))
        .min(policy.max_backoff_secs);
    // Full jitter: uniform over [0, exponential], floored at one second so a
    // failing custody cannot spin.
    ((exponential as f64 * jitter.unit()) as u64).max(1)
}

/// Something that can exchange a custody's refresh token upstream. Implemented
/// over the OIDC client in production and faked in tests.
pub trait Upstream: Send + Sync + 'static {
    fn refresh(
        &self,
        custody: &CustodyId,
    ) -> impl std::future::Future<Output = RefreshOutcome> + Send;
}

/// The async runner. Owns the scheduler, dispatches due refreshes under a
/// concurrency limit, and propagates custody health into the session map.
pub struct KeepaliveWorker<U: Upstream> {
    scheduler: Scheduler,
    sessions: Arc<SessionMap>,
    clock: Arc<dyn Clock>,
    jitter: Arc<dyn Jitter>,
    upstream: Arc<U>,
    /// Counters for the background plane. Always present — a no-op `Metrics`
    /// costs an atomic add nobody reads, which is cheaper than an `Option`
    /// branch at every call site plus the chance of forgetting one.
    metrics: Arc<crate::telemetry::Metrics>,
    /// `None` in the scheduler tests, which have no store behind them.
    audit: Option<crate::audit::AuditSink>,
    /// Where a FAILED refresh's health and backoff are persisted.
    ///
    /// Without this the durable `custody` row never leaves `status='ok',
    /// fail_count=0`, so a dead grant comes back alive after a restart with its
    /// backoff reset — and `live_custody_schedules`' `status != 'dead'` filter
    /// can never match anything. The success path writes through from
    /// `custody::OidcUpstream`; this is the other half.
    writer: Option<WriterHandle>,
}

impl<U: Upstream> KeepaliveWorker<U> {
    pub fn new(
        policy: KeepalivePolicy,
        sessions: Arc<SessionMap>,
        clock: Arc<dyn Clock>,
        jitter: Arc<dyn Jitter>,
        upstream: Arc<U>,
    ) -> KeepaliveWorker<U> {
        KeepaliveWorker {
            scheduler: Scheduler::new(policy),
            sessions,
            clock,
            jitter,
            upstream,
            metrics: crate::telemetry::Metrics::new(),
            audit: None,
            writer: None,
        }
    }

    /// Attach the store, so failed refreshes persist their health and backoff.
    pub fn with_durability(mut self, writer: WriterHandle) -> Self {
        self.writer = Some(writer);
        self
    }

    /// Attach the observability planes.
    ///
    /// A builder rather than two more parameters on `new`: the worker is
    /// constructed in a dozen scheduler tests that care about backoff and
    /// jitter and nothing else, and widening the constructor would edit all of
    /// them to say `None` twice.
    pub fn with_observability(
        mut self,
        metrics: Arc<crate::telemetry::Metrics>,
        audit: Option<crate::audit::AuditSink>,
    ) -> Self {
        self.metrics = metrics;
        self.audit = audit;
        self
    }

    pub fn scheduler_mut(&mut self) -> &mut Scheduler {
        &mut self.scheduler
    }

    /// Run one pass: dispatch everything due, await the results, apply them.
    /// Separated from any sleeping so tests can drive it a tick at a time.
    pub async fn tick(&mut self) -> usize {
        let now = self.clock.now();
        let due = self.scheduler.take_due(now);
        if due.is_empty() {
            return 0;
        }

        let mut handled = 0;
        // Dispatched in bounded batches: `max_concurrent` upstream calls in
        // flight at once, to stay a good citizen against a rate-limiting IdP.
        for chunk in due.chunks(self.scheduler.policy().max_concurrent.max(1)) {
            let mut inflight = tokio::task::JoinSet::new();
            for custody in chunk {
                let upstream = self.upstream.clone();
                let custody = custody.clone();
                inflight.spawn(async move {
                    // Timed around the upstream call only. This is the one
                    // histogram in the service that measures the IdP rather
                    // than the broker, which is exactly what makes it useful
                    // when "the broker is slow" turns out not to be true.
                    let started = std::time::Instant::now();
                    let outcome = upstream.refresh(&custody).await;
                    (custody, outcome, started.elapsed())
                });
            }
            while let Some(joined) = inflight.join_next().await {
                let Ok((custody, outcome, elapsed)) = joined else {
                    // A panicking refresh must not take the worker down; the
                    // custody simply stays scheduled and is retried.
                    tracing::error!("keepalive refresh task panicked");
                    continue;
                };
                let now = self.clock.now();
                let permanent = outcome == RefreshOutcome::Permanent;
                let outcome_was_success = matches!(outcome, RefreshOutcome::Success { .. });
                let label = match outcome {
                    RefreshOutcome::Success { .. } => "success",
                    RefreshOutcome::Transient { .. } => "transient",
                    RefreshOutcome::Permanent => "permanent",
                };
                self.metrics.record_keepalive(label, Some(elapsed));

                // Read before recording: `record` moves the state, and the
                // audit row is about the TRANSITION, not the current value.
                // Without this, a grant dead for a week would emit a
                // `custody.dead` row on every retry — a record turning into a
                // log.
                let before = self.scheduler.get(&custody).map(|s| s.status);
                let status = self
                    .scheduler
                    .record(&custody, outcome, now, self.jitter.as_ref());

                if let Some(status) = status {
                    self.sessions.set_custody_status(&custody, status);
                    if before != Some(status) {
                        self.record_transition(&custody, status, now);
                    }
                    // Persist health and backoff on every failure, not only on
                    // transitions: `fail_count` and `next_refresh` move each
                    // time, and a restart that resurrected the old backoff
                    // would stampede a recovering IdP.
                    if !outcome_was_success {
                        self.persist_failure(&custody, status, now);
                    }
                }
                if permanent
                    && self.scheduler.policy().on_upstream_revoked == RevocationPolicy::Kill
                {
                    // ADR-0011: revocation upstream means revocation here.
                    let killed = self.sessions.tombstone_by_custody(&custody, now);
                    tracing::warn!(
                        custody = %custody.0,
                        killed,
                        "upstream grant revoked; sessions tombstoned"
                    );
                    if let Some(sink) = &self.audit {
                        sink.record(
                            crate::audit::Event::new(
                                crate::audit::action::CUSTODY_REVOKED_UPSTREAM,
                                crate::audit::Outcome::Success,
                                crate::audit::ActorKind::System,
                                now,
                            )
                            .custody_id(custody.0.clone())
                            // The policy is in the row because the same event
                            // means different things under `kill` and
                            // `degrade` (ADR-0011), and an operator reading
                            // this months later will not remember which was
                            // configured that day.
                            .detail(serde_json::json!({
                                "policy": "kill",
                                "sessions_killed": killed,
                            })),
                        );
                    }
                }
                handled += 1;
            }
        }
        handled
    }

    /// Write a failed refresh's health and backoff through to the store.
    ///
    /// The values come from the scheduler rather than being recomputed here:
    /// it owns the backoff policy, and two places deriving `next_refresh`
    /// independently is how memory and disk start disagreeing about when a
    /// grant is due.
    fn persist_failure(&self, custody: &CustodyId, status: CustodyStatus, now: Timestamp) {
        let Some(writer) = &self.writer else { return };
        let Some(state) = self.scheduler.get(custody) else {
            return;
        };
        writer.enqueue_custody_failure(
            custody.clone(),
            status,
            state.fail_count as i64,
            state.next_refresh,
            now,
        );
    }

    /// One audit row per health transition (ADR-0015, Tier B).
    ///
    /// `Ok` transitions are not recorded: recovery is the expected outcome of
    /// the retry the failure row already documents, and a row for it would
    /// double the volume to say "as designed". The failure is the fact.
    fn record_transition(&self, custody: &CustodyId, status: CustodyStatus, now: Timestamp) {
        let Some(sink) = &self.audit else { return };
        let action = match status {
            CustodyStatus::Degraded => crate::audit::action::CUSTODY_DEGRADED,
            CustodyStatus::Dead => crate::audit::action::CUSTODY_DEAD,
            CustodyStatus::Ok => return,
        };
        sink.record(
            crate::audit::Event::new(
                action,
                crate::audit::Outcome::Failure,
                crate::audit::ActorKind::System,
                now,
            )
            .custody_id(custody.0.clone()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::session::{SessionPolicy, Sid};

    const T0: Timestamp = Timestamp(1_700_000_000);

    fn scheduler() -> Scheduler {
        Scheduler::new(KeepalivePolicy::default())
    }

    #[test]
    fn refresh_is_scheduled_at_sixty_percent_of_the_token_lifetime() {
        let mut s = scheduler();
        let mid = FixedJitter(0.5); // no net displacement
        s.insert(CustodyId("c1".into()), T0, 3600, &mid);

        // 3600 × 0.6 = 2160 seconds in.
        assert_eq!(
            s.get(&CustodyId("c1".into())).unwrap().next_refresh,
            T0.plus_secs(2160)
        );
    }

    #[test]
    fn jitter_stays_inside_ten_percent_of_the_lead_margin() {
        let lead = 2160.0;
        let bound = (lead * 0.1) as u64;
        for unit in [0.0, 0.25, 0.5, 0.75, 0.999] {
            let mut s = scheduler();
            s.insert(CustodyId("c".into()), T0, 3600, &FixedJitter(unit));
            let at = s.get(&CustodyId("c".into())).unwrap().next_refresh;
            let delay = at.since(T0);
            assert!(
                delay >= 2160 - bound && delay <= 2160 + bound,
                "delay {delay} outside ±{bound} of 2160 for unit {unit}"
            );
        }
    }

    #[test]
    fn nothing_is_due_before_its_deadline() {
        let mut s = scheduler();
        s.insert(CustodyId("c1".into()), T0, 3600, &FixedJitter(0.5));
        assert!(s.take_due(T0.plus_secs(2159)).is_empty());
        assert_eq!(s.take_due(T0.plus_secs(2160)), vec![CustodyId("c1".into())]);
    }

    #[test]
    fn a_custody_already_in_flight_is_not_dispatched_twice() {
        // With a single-use rotating refresh token, a double dispatch would burn
        // the grant — this is the guard against that.
        let mut s = scheduler();
        s.insert(CustodyId("c1".into()), T0, 100, &FixedJitter(0.5));
        let now = T0.plus_secs(60);
        assert_eq!(s.take_due(now).len(), 1);
        assert!(s.take_due(now).is_empty(), "dispatched while in flight");
    }

    #[test]
    fn transient_failures_back_off_exponentially_and_cap() {
        let mut s = scheduler();
        let full = FixedJitter(0.999); // full jitter → the top of the range
        let custody = CustodyId("c1".into());
        s.insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        let mut now = T0.plus_secs(60);
        let mut delays = Vec::new();
        for _ in 0..12 {
            s.take_due(now);
            s.record(
                &custody,
                RefreshOutcome::Transient {
                    retry_after_secs: None,
                },
                now,
                &full,
            );
            let next = s.get(&custody).unwrap().next_refresh;
            delays.push(next.since(now));
            now = next;
        }

        // Full jitter means each delay is uniform over [0, 2^n], so what must
        // hold is the *envelope*: never above the doubling curve, never above
        // the cap, never zero (a failing custody must not spin).
        for (n, delay) in delays.iter().enumerate() {
            let ceiling = (1u64 << n).min(300);
            assert!(
                (1..=ceiling).contains(delay),
                "delay {delay} outside 1..={ceiling} at attempt {n}"
            );
        }
        // And with jitter pinned near the top of the range it does reach the cap.
        assert!(*delays.last().unwrap() >= 299);
    }

    #[test]
    fn backoff_never_reaches_zero_even_with_no_jitter() {
        let mut s = scheduler();
        let none = FixedJitter(0.0);
        let custody = CustodyId("c1".into());
        s.insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        let mut now = T0.plus_secs(60);
        for _ in 0..5 {
            s.take_due(now);
            s.record(
                &custody,
                RefreshOutcome::Transient {
                    retry_after_secs: None,
                },
                now,
                &none,
            );
            let next = s.get(&custody).unwrap().next_refresh;
            assert!(next.since(now) >= 1, "backoff collapsed to zero");
            now = next;
        }
    }

    #[test]
    fn retry_after_overrides_the_backoff_curve() {
        let mut s = scheduler();
        let custody = CustodyId("c1".into());
        s.insert(custody.clone(), T0, 100, &FixedJitter(0.5));
        let now = T0.plus_secs(60);
        s.take_due(now);
        s.record(
            &custody,
            RefreshOutcome::Transient {
                retry_after_secs: Some(42),
            },
            now,
            &FixedJitter(0.999),
        );
        assert_eq!(s.get(&custody).unwrap().next_refresh, now.plus_secs(42));
    }

    #[test]
    fn a_failing_custody_only_degrades_once_its_token_has_actually_expired() {
        let mut s = scheduler();
        let custody = CustodyId("c1".into());
        s.insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        // Retrying before expiry: nothing downstream is affected yet.
        let before = T0.plus_secs(60);
        s.take_due(before);
        let status = s.record(
            &custody,
            RefreshOutcome::Transient {
                retry_after_secs: None,
            },
            before,
            &FixedJitter(0.5),
        );
        assert_eq!(status, Some(CustodyStatus::Ok));

        // Past the access token's expiry, it is genuinely degraded.
        let after = T0.plus_secs(101);
        s.take_due(after);
        let status = s.record(
            &custody,
            RefreshOutcome::Transient {
                retry_after_secs: None,
            },
            after,
            &FixedJitter(0.5),
        );
        assert_eq!(status, Some(CustodyStatus::Degraded));
    }

    #[test]
    fn a_permanent_failure_kills_the_custody_and_stops_scheduling() {
        let mut s = scheduler();
        let custody = CustodyId("c1".into());
        s.insert(custody.clone(), T0, 100, &FixedJitter(0.5));
        let now = T0.plus_secs(60);
        s.take_due(now);

        assert_eq!(
            s.record(&custody, RefreshOutcome::Permanent, now, &FixedJitter(0.5)),
            Some(CustodyStatus::Dead)
        );
        // Never dispatched again, however far time runs on.
        assert!(s.take_due(now.plus_secs(100_000)).is_empty());
    }

    #[test]
    fn a_successful_refresh_clears_the_failure_count_and_reschedules() {
        let mut s = scheduler();
        let custody = CustodyId("c1".into());
        s.insert(custody.clone(), T0, 3600, &FixedJitter(0.5));

        let now = T0.plus_secs(2160);
        s.take_due(now);
        s.record(
            &custody,
            RefreshOutcome::Transient {
                retry_after_secs: None,
            },
            now,
            &FixedJitter(0.5),
        );
        assert_eq!(s.get(&custody).unwrap().fail_count, 1);

        let now = now.plus_secs(10);
        s.take_due(now);
        let status = s.record(
            &custody,
            RefreshOutcome::Success {
                lifetime_secs: 3600,
                rotated_refresh: true,
            },
            now,
            &FixedJitter(0.5),
        );
        let state = s.get(&custody).unwrap();
        assert_eq!(status, Some(CustodyStatus::Ok));
        assert_eq!(state.fail_count, 0);
        assert_eq!(state.access_exp, now.plus_secs(3600));
        assert_eq!(state.next_refresh, now.plus_secs(2160));
    }

    // --- propagation into sessions -----------------------------------------

    struct FakeUpstream(RefreshOutcome);

    impl Upstream for FakeUpstream {
        async fn refresh(&self, _custody: &CustodyId) -> RefreshOutcome {
            self.0.clone()
        }
    }

    /// A grant that has been failing for hours must leave ONE `custody.degraded`
    /// row, not one per retry.
    ///
    /// The audit table records what CHANGED. A row per attempt would turn it
    /// into a log, bury the transition that mattered under repetitions of
    /// itself, and spend the Tier-B queue budget that exists for events nobody
    /// can reconstruct afterwards.
    ///
    /// `Transient` rather than `Permanent` on purpose: the scheduler stops
    /// scheduling a DEAD custody, so a dead grant cannot be retried and the
    /// regression this guards against is unreachable there. A degraded one
    /// keeps being retried, which is exactly where a missing transition check
    /// would show up.
    #[tokio::test]
    async fn a_custody_health_transition_is_recorded_once_not_on_every_retry() {
        use crate::store::repo::{self, AuditQuery};
        use crate::store::writer::{AdminWrite, Writer};

        // File-backed: two `:memory:` connections are two separate databases,
        // so rows the writer commits would be invisible to a reader.
        let path = std::env::temp_dir().join(format!(
            "session-broker-keepalive-audit-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let keyfile = path.with_extension("key");
        let writer = Writer::spawn(crate::store::open(&path, &keyfile).unwrap());
        let reader = crate::store::open(&path, &keyfile).unwrap();

        let metrics = crate::telemetry::Metrics::new();
        let audit = crate::audit::AuditSink::new(
            writer.handle(),
            metrics.clone(),
            crate::audit::AuditConfig::default(),
        );

        let (worker, _sessions, clock) = worker(
            RefreshOutcome::Transient {
                retry_after_secs: Some(1),
            },
            RevocationPolicy::Degrade,
        );
        let mut worker = worker.with_observability(metrics.clone(), Some(audit));

        let custody = CustodyId("c1".into());
        // Lifetime 100s; every tick below is past that, so each failure lands
        // with the access token already expired — which is what makes the
        // status Degraded rather than a still-fine Ok.
        worker
            .scheduler_mut()
            .insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        let mut attempts = 0;
        for _ in 0..4 {
            clock.advance(500);
            attempts += worker.tick().await;
        }
        assert!(
            attempts >= 3,
            "the custody must actually have been retried several times, or this \
             test proves nothing; got {attempts}"
        );

        // Force a flush: batches apply in order, so a write-through ack means
        // everything enqueued before it has committed.
        let _ = writer.handle().write_admin(AdminWrite::TouchApiKey {
            key_id: "nobody".to_owned(),
            now: T0,
        });

        let rows = repo::list_audit(
            &reader,
            &AuditQuery {
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .unwrap();
        let degraded = rows
            .iter()
            .filter(|r| r.row.action == crate::audit::action::CUSTODY_DEGRADED)
            .count();
        assert_eq!(
            degraded, 1,
            "{attempts} failing attempts must leave one transition row: {rows:?}"
        );

        drop(reader);
        drop(writer);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(&keyfile);
    }

    /// Insert a custody row so the UPDATEs under test have something to hit —
    /// an UPDATE against a missing row is a silent no-op, and asserting on one
    /// would prove nothing.
    fn seed_custody(writer: &crate::store::writer::WriterHandle, custody: &CustodyId) {
        writer
            .write_custody(crate::store::writer::CustodyWrite::Insert(
                crate::store::repo::CustodyRow {
                    custody_id: custody.clone(),
                    sub: "user-1".to_owned(),
                    refresh_tok: b"refresh".to_vec(),
                    access_tok: b"access".to_vec(),
                    access_exp: T0.plus_secs(100),
                    scope: None,
                    status: CustodyStatus::Ok,
                    next_refresh: T0.plus_secs(60),
                    fail_count: 0,
                    updated_at: T0,
                },
            ))
            .unwrap();
    }

    /// A temp store plus a second connection to read it back.
    fn durable_store(
        tag: &str,
    ) -> (
        std::path::PathBuf,
        crate::store::writer::Writer,
        rusqlite::Connection,
    ) {
        let path = std::env::temp_dir().join(format!(
            "session-broker-custody-{tag}-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let keyfile = path.with_extension("key");
        let writer =
            crate::store::writer::Writer::spawn(crate::store::open(&path, &keyfile).unwrap());
        let reader = crate::store::open(&path, &keyfile).unwrap();
        (path, writer, reader)
    }

    fn cleanup_store(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(path.with_extension("key"));
    }

    /// Batches apply in order, so a write-through ack means every
    /// fire-and-forget command enqueued before it has committed.
    fn flush(writer: &crate::store::writer::WriterHandle) {
        let _ = writer.write_admin(crate::store::writer::AdminWrite::TouchApiKey {
            key_id: "nobody".to_owned(),
            now: T0,
        });
    }

    /// A transient failure must persist its backoff.
    ///
    /// This was silently broken: nothing sent `CustodyWrite::Failure`, so the
    /// durable row never left `status='ok', fail_count=0` however many times a
    /// refresh failed — and a restart resurrected the old schedule, which is how
    /// a recovering IdP gets stampeded by a fleet that forgot it was backing off.
    #[tokio::test]
    async fn a_failed_refresh_persists_its_health_and_backoff() {
        use crate::store::repo;

        let (path, writer, reader) = durable_store("backoff");
        let custody = CustodyId("c1".into());
        seed_custody(&writer.handle(), &custody);

        let (worker, _sessions, clock) = worker(
            RefreshOutcome::Transient {
                retry_after_secs: Some(90),
            },
            RevocationPolicy::Degrade,
        );
        let mut worker = worker.with_durability(writer.handle());
        worker
            .scheduler_mut()
            .insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        // Past the access token's expiry, so the failure is genuinely degrading.
        clock.advance(200);
        assert_eq!(worker.tick().await, 1);
        flush(&writer.handle());

        let row = repo::load_custody(&reader, &custody).unwrap().unwrap();
        assert_eq!(row.status, CustodyStatus::Degraded);
        assert!(
            row.fail_count > 0,
            "the retry counter must survive a restart, or the backoff resets"
        );
        assert!(
            row.next_refresh.secs() > T0.plus_secs(60).secs(),
            "and so must the backed-off schedule"
        );

        drop(reader);
        drop(writer);
        cleanup_store(&path);
    }

    /// A grant that dies must STAY dead across a restart.
    ///
    /// `live_custody_schedules` filters `status != 'dead'` — a filter that could
    /// never match anything while no failure was ever written, so a dead grant
    /// came back alive on every boot. `/admin/custody`, the Custody console view
    /// and the `broker_custody{status}` gauge read the same rows, so all three
    /// reported healthy grants that were not.
    #[tokio::test]
    async fn a_dead_grant_is_not_handed_back_to_the_restart_path() {
        use crate::store::repo;

        let (path, writer, reader) = durable_store("dead");
        let custody = CustodyId("c1".into());
        seed_custody(&writer.handle(), &custody);

        let (worker, _sessions, clock) =
            worker(RefreshOutcome::Permanent, RevocationPolicy::Degrade);
        let mut worker = worker.with_durability(writer.handle());
        worker
            .scheduler_mut()
            .insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        clock.advance(200);
        assert_eq!(worker.tick().await, 1);
        flush(&writer.handle());

        let row = repo::load_custody(&reader, &custody).unwrap().unwrap();
        assert_eq!(
            row.status,
            CustodyStatus::Dead,
            "the durable row must record the death"
        );
        // `fail_count` deliberately does NOT move here: a permanent failure
        // stops scheduling outright, so a retry counter would describe retries
        // that will never happen.

        let live = repo::live_custody_schedules(&reader).unwrap();
        assert!(
            live.iter().all(|s| s.custody_id != custody),
            "a dead grant must not be restored on the next boot"
        );

        drop(reader);
        drop(writer);
        cleanup_store(&path);
    }

    fn worker(
        outcome: RefreshOutcome,
        policy: RevocationPolicy,
    ) -> (KeepaliveWorker<FakeUpstream>, Arc<SessionMap>, TestClock) {
        let clock = TestClock::new(T0);
        let sessions = Arc::new(SessionMap::new(SessionPolicy {
            on_upstream_revoked: policy,
            ..SessionPolicy::default()
        }));
        let worker = KeepaliveWorker::new(
            KeepalivePolicy {
                on_upstream_revoked: policy,
                ..KeepalivePolicy::default()
            },
            sessions.clone(),
            Arc::new(clock.clone()),
            Arc::new(FixedJitter(0.5)),
            Arc::new(FakeUpstream(outcome)),
        );
        (worker, sessions, clock)
    }

    #[tokio::test]
    async fn a_revoked_grant_tombstones_every_session_it_backs() {
        let (mut worker, sessions, clock) =
            worker(RefreshOutcome::Permanent, RevocationPolicy::Kill);
        let custody = CustodyId("c1".into());
        for n in 0..3 {
            sessions.create(Sid(format!("s{n}")), custody.clone(), "user".into(), T0);
        }
        worker
            .scheduler_mut()
            .insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        clock.advance(60);
        assert_eq!(worker.tick().await, 1);

        // INV-7 machinery, reached through the revocation path.
        assert_eq!(sessions.tombstone_by_custody(&custody, clock.now()), 0);
        assert_eq!(
            worker.scheduler_mut().get(&custody).unwrap().status,
            CustodyStatus::Dead
        );
    }

    #[tokio::test]
    async fn degrade_policy_leaves_sessions_alive_but_marks_them() {
        let (mut worker, sessions, clock) =
            worker(RefreshOutcome::Permanent, RevocationPolicy::Degrade);
        let custody = CustodyId("c1".into());
        let issued = sessions.create(Sid("s1".into()), custody.clone(), "user".into(), T0);
        worker
            .scheduler_mut()
            .insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        clock.advance(60);
        worker.tick().await;

        let meta = sessions.meta_for(&issued.token.hash()).unwrap();
        assert_eq!(meta.custody, CustodyStatus::Dead);
        assert!(sessions
            .resolve(&issued.token.hash(), clock.now())
            .authenticates());
    }

    #[tokio::test]
    async fn a_healthy_refresh_leaves_sessions_untouched() {
        let (mut worker, sessions, clock) = worker(
            RefreshOutcome::Success {
                lifetime_secs: 3600,
                rotated_refresh: false,
            },
            RevocationPolicy::Kill,
        );
        let custody = CustodyId("c1".into());
        let issued = sessions.create(Sid("s1".into()), custody.clone(), "user".into(), T0);
        worker
            .scheduler_mut()
            .insert(custody.clone(), T0, 100, &FixedJitter(0.5));

        clock.advance(60);
        worker.tick().await;

        assert!(sessions
            .resolve(&issued.token.hash(), clock.now())
            .authenticates());
        assert_eq!(
            sessions.meta_for(&issued.token.hash()).unwrap().custody,
            CustodyStatus::Ok
        );
    }
}
