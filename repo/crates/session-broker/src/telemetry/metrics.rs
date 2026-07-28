//! Prometheus text exposition, hand-rolled from atomics (ADR-0014).
//!
//! No metrics crate, following `infrastructure/query-cache`'s ADR-0015 for the
//! same three reasons: the metric set is fixed, label cardinality is bounded by
//! the router (labels are matched route *patterns*, never raw paths — INV-12),
//! and the 0.0.4 text format is a few dozen lines of string assembly.
//!
//! ## The cost this pays on the hot path
//!
//! One atomic add per counter, plus one per histogram bucket observation. Label
//! lookup takes a read lock, and a write lock only the first time a label
//! combination is seen — a two-phase lookup, so the read guard is released
//! before the write lock is taken (the lock-upgrade deadlock ArrowRef hit).
//!
//! `/authz` and `/session/refresh` produce **only** this. No audit row, no store
//! write, no allocation on the steady-state path (the label key is looked up by
//! reference before any `to_owned`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Bucket bounds in seconds.
///
/// Starts at **50 µs**, not the conventional 1 ms: the product claim is that
/// `/session/refresh` answers in microseconds (INV-8), and a histogram whose
/// first bucket is 1 ms cannot show the difference between 40 µs and 900 µs. It
/// would report "everything is in the fastest bucket" right up until the claim
/// stopped being true.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
    1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Default)]
pub struct Histogram {
    buckets: Vec<AtomicU64>,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new() -> Histogram {
        Histogram {
            buckets: (0..LATENCY_BUCKETS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, elapsed: std::time::Duration) {
        let secs = elapsed.as_secs_f64();
        // Cumulative buckets: every bound at or above the observation counts it,
        // which is what `le` means in the text format.
        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// A label-keyed family of counters or histograms.
///
/// Keys are owned `Vec<String>` but only allocated on first sight of a label
/// combination; steady state is a read-locked lookup by slice.
#[derive(Debug, Default)]
struct Family<T> {
    inner: RwLock<HashMap<Vec<String>, Arc<T>>>,
}

impl<T> Family<T> {
    fn get_or_insert(&self, labels: &[&str], make: impl Fn() -> T) -> Arc<T> {
        {
            let guard = self.inner.read().expect("metrics family lock poisoned");
            // Compare without allocating: the steady-state path.
            if let Some(found) = guard
                .iter()
                .find(|(k, _)| k.len() == labels.len() && k.iter().zip(labels).all(|(a, b)| a == b))
            {
                return found.1.clone();
            }
        }
        // Read guard released before the write lock is taken.
        let key: Vec<String> = labels.iter().map(|s| (*s).to_owned()).collect();
        let mut guard = self.inner.write().expect("metrics family lock poisoned");
        guard.entry(key).or_insert_with(|| Arc::new(make())).clone()
    }

    fn snapshot(&self) -> Vec<(Vec<String>, Arc<T>)> {
        let guard = self.inner.read().expect("metrics family lock poisoned");
        let mut rows: Vec<_> = guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }
}

/// Gauges that are cheaper to read at scrape time than to maintain.
///
/// Session and custody counts live in the session map and the store, which
/// already know them exactly. Mirroring them into atomics would add a write to
/// every session mutation to produce a number that can drift; sampling them once
/// per scrape cannot drift at all.
#[derive(Debug, Default, Clone)]
pub struct GaugeSnapshot {
    pub sessions_live: u64,
    pub generations_live: u64,
    pub event_subscribers: u64,
    pub custody_ok: u64,
    pub custody_degraded: u64,
    pub custody_dead: u64,
    pub audit_rows: u64,
    /// Age of the oldest retained audit row, in seconds. `0` when the table is
    /// empty — distinguishable from a real value because `audit_rows` is 0 too.
    pub audit_oldest_seconds: u64,
    pub log_level_override_active: bool,
}

/// Every series the broker exposes. One instance, held in `AppState` and in the
/// internal lane's state.
#[derive(Debug, Default)]
pub struct Metrics {
    http_requests: Family<AtomicU64>,
    http_duration: Family<Histogram>,
    authz_decisions: Family<AtomicU64>,
    session_refresh: Family<AtomicU64>,
    token_exchanges: Family<AtomicU64>,
    session_anomalies: Family<AtomicU64>,
    keepalive_refresh: Family<AtomicU64>,
    keepalive_duration: Histogram,
    audit_recorded: Family<AtomicU64>,
    audit_dropped: AtomicU64,
    audit_failed: AtomicU64,
    audit_queue_depth: AtomicI64,
}

impl Metrics {
    pub fn new() -> Arc<Metrics> {
        Arc::new(Metrics {
            keepalive_duration: Histogram::new(),
            ..Metrics::default()
        })
    }

    /// `lane` is `public`, `internal` or `admin`; `route` is the *matched* axum
    /// path pattern, never the raw URI — a raw path carries `return_to` and
    /// `code` (INV-12) and would blow cardinality apart besides.
    pub fn record_request(
        &self,
        lane: &str,
        route: &str,
        status: u16,
        elapsed: std::time::Duration,
    ) {
        let status = status.to_string();
        self.http_requests
            .get_or_insert(&[lane, route, &status], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        self.http_duration
            .get_or_insert(&[lane, route], Histogram::new)
            .observe(elapsed);
    }

    /// The platform's per-request lane. A denial is a counter and a log line,
    /// never an audit row: it changed nothing (ADR-0015).
    pub fn record_authz(&self, decision: &str, reason: &str) {
        self.authz_decisions
            .get_or_insert(&[decision, reason], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `outcome` ∈ `rotated | coalesced | reused | refused`.
    pub fn record_refresh(&self, outcome: &str) {
        self.session_refresh
            .get_or_insert(&[outcome], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_token_exchange(&self, outcome: &str) {
        self.token_exchanges
            .get_or_insert(&[outcome], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_anomaly(&self, kind: &str) {
        self.session_anomalies
            .get_or_insert(&[kind], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_keepalive(&self, outcome: &str, elapsed: Option<std::time::Duration>) {
        self.keepalive_refresh
            .get_or_insert(&[outcome], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        if let Some(elapsed) = elapsed {
            self.keepalive_duration.observe(elapsed);
        }
    }

    pub fn record_audit(&self, tier: &str) {
        self.audit_recorded
            .get_or_insert(&[tier], || AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A hole in the security record. Alert on any increase (ADR-0015).
    pub fn record_audit_dropped(&self, count: u64) {
        self.audit_dropped.fetch_add(count, Ordering::Relaxed);
    }

    /// A Tier-A transaction failed, so an admin operation was refused rather
    /// than performed unrecorded.
    pub fn record_audit_failed(&self) {
        self.audit_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_audit_queue_depth(&self, depth: i64) {
        self.audit_queue_depth.store(depth, Ordering::Relaxed);
    }

    pub fn audit_dropped_total(&self) -> u64 {
        self.audit_dropped.load(Ordering::Relaxed)
    }

    pub fn audit_failed_total(&self) -> u64 {
        self.audit_failed.load(Ordering::Relaxed)
    }

    /// Prometheus text format 0.0.4.
    pub fn render(&self, gauges: &GaugeSnapshot) -> String {
        let mut out = String::with_capacity(8 * 1024);

        writeln!(out, "# HELP broker_build_info Build metadata.").ok();
        writeln!(out, "# TYPE broker_build_info gauge").ok();
        writeln!(
            out,
            "broker_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )
        .ok();

        counter_family(
            &mut out,
            "broker_http_requests_total",
            "HTTP requests by lane, matched route pattern and status.",
            &["lane", "route", "status"],
            &self.http_requests,
        );
        histogram_family(
            &mut out,
            "broker_http_request_duration_seconds",
            "HTTP handler latency by lane and matched route pattern.",
            &["lane", "route"],
            &self.http_duration,
        );
        counter_family(
            &mut out,
            "broker_authz_decisions_total",
            "Edge authorisation decisions. This lane is on every platform request.",
            &["decision", "reason"],
            &self.authz_decisions,
        );
        counter_family(
            &mut out,
            "broker_session_refresh_total",
            "Session refresh outcomes. 'coalesced' is non-invalidating rotation working.",
            &["outcome"],
            &self.session_refresh,
        );
        counter_family(
            &mut out,
            "broker_token_exchanges_total",
            "Upstream token exchanges on /internal/token.",
            &["outcome"],
            &self.token_exchanges,
        );
        counter_family(
            &mut out,
            "broker_session_anomalies_total",
            "INV-6a signals. Signal, not revocation — a nonzero rate is worth looking at.",
            &["kind"],
            &self.session_anomalies,
        );
        counter_family(
            &mut out,
            "broker_keepalive_refresh_total",
            "Background upstream-token renewals.",
            &["outcome"],
            &self.keepalive_refresh,
        );
        histogram(
            &mut out,
            "broker_keepalive_upstream_duration_seconds",
            "Time spent calling the upstream IdP. The only histogram here that measures the IdP.",
            "",
            &self.keepalive_duration,
        );
        counter_family(
            &mut out,
            "broker_audit_recorded_total",
            "Audit rows written, by tier.",
            &["tier"],
            &self.audit_recorded,
        );

        gauge(
            &mut out,
            "broker_sessions_live",
            "Live sessions.",
            gauges.sessions_live as f64,
        );
        gauge(
            &mut out,
            "broker_generations_live",
            "Live cookie generations across all sessions (bounded by MAX_LIVE_GENS per session).",
            gauges.generations_live as f64,
        );
        gauge(
            &mut out,
            "broker_session_events_subscribers",
            "Open /session/events SSE streams.",
            gauges.event_subscribers as f64,
        );

        writeln!(out, "# HELP broker_custody Upstream grants by health.").ok();
        writeln!(out, "# TYPE broker_custody gauge").ok();
        writeln!(out, "broker_custody{{status=\"ok\"}} {}", gauges.custody_ok).ok();
        writeln!(
            out,
            "broker_custody{{status=\"degraded\"}} {}",
            gauges.custody_degraded
        )
        .ok();
        writeln!(
            out,
            "broker_custody{{status=\"dead\"}} {}",
            gauges.custody_dead
        )
        .ok();

        counter(
            &mut out,
            "broker_audit_dropped_total",
            "Tier-B audit events dropped at the queue bound. NONZERO MEANS THE RECORD HAS A HOLE.",
            self.audit_dropped.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "broker_audit_failed_total",
            "Tier-A audit writes that failed, each of which refused an admin operation.",
            self.audit_failed.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "broker_audit_queue_depth",
            "Tier-B audit events enqueued and not yet committed.",
            self.audit_queue_depth.load(Ordering::Relaxed) as f64,
        );
        gauge(
            &mut out,
            "broker_audit_rows",
            "Rows in the retention window.",
            gauges.audit_rows as f64,
        );
        gauge(
            &mut out,
            "broker_audit_oldest_seconds",
            "Age of the oldest retained audit row.",
            gauges.audit_oldest_seconds as f64,
        );
        gauge(
            &mut out,
            "broker_log_level_override_active",
            "1 while a temporary verbosity override is in force.",
            u8::from(gauges.log_level_override_active) as f64,
        );

        out
    }
}

// --- exposition helpers -------------------------------------------------

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn label_set(names: &[&str], values: &[String]) -> String {
    if names.is_empty() {
        return String::new();
    }
    let pairs: Vec<String> = names
        .iter()
        .zip(values)
        .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} counter").ok();
    writeln!(out, "{name} {value}").ok();
}

fn gauge(out: &mut String, name: &str, help: &str, value: f64) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} gauge").ok();
    writeln!(out, "{name} {value}").ok();
}

fn counter_family(
    out: &mut String,
    name: &str,
    help: &str,
    labels: &[&str],
    family: &Family<AtomicU64>,
) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} counter").ok();
    for (key, value) in family.snapshot() {
        writeln!(
            out,
            "{name}{} {}",
            label_set(labels, &key),
            value.load(Ordering::Relaxed)
        )
        .ok();
    }
}

fn histogram_family(
    out: &mut String,
    name: &str,
    help: &str,
    labels: &[&str],
    family: &Family<Histogram>,
) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} histogram").ok();
    for (key, hist) in family.snapshot() {
        let base = label_set(labels, &key);
        write_histogram_body(out, name, &base, labels, &key, &hist);
    }
}

fn histogram(out: &mut String, name: &str, help: &str, _labels: &str, hist: &Histogram) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} histogram").ok();
    write_histogram_body(out, name, "", &[], &[], hist);
}

fn write_histogram_body(
    out: &mut String,
    name: &str,
    base: &str,
    labels: &[&str],
    key: &[String],
    hist: &Histogram,
) {
    for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
        let mut pairs: Vec<String> = labels
            .iter()
            .zip(key)
            .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
            .collect();
        pairs.push(format!("le=\"{bound}\""));
        writeln!(
            out,
            "{name}_bucket{{{}}} {}",
            pairs.join(","),
            hist.buckets[i].load(Ordering::Relaxed)
        )
        .ok();
    }
    let count = hist.count.load(Ordering::Relaxed);
    let mut inf: Vec<String> = labels
        .iter()
        .zip(key)
        .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
        .collect();
    inf.push("le=\"+Inf\"".to_owned());
    writeln!(out, "{name}_bucket{{{}}} {count}", inf.join(",")).ok();
    writeln!(
        out,
        "{name}_sum{base} {}",
        hist.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    )
    .ok();
    writeln!(out, "{name}_count{base} {count}").ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_cumulative_and_start_below_a_millisecond() {
        // The claim this histogram exists to hold the service to: a refresh
        // answering in 80 microseconds must land in a bucket that says so, not
        // in an undifferentiated "under 1ms" bin.
        assert!(LATENCY_BUCKETS[0] < 0.001);

        let m = Metrics::new();
        m.record_request(
            "public",
            "/session/refresh",
            200,
            std::time::Duration::from_micros(80),
        );
        let text = m.render(&GaugeSnapshot::default());

        assert!(
            text.contains("broker_http_request_duration_seconds_bucket{lane=\"public\",route=\"/session/refresh\",le=\"0.0001\"} 1"),
            "80us must fall in the 100us bucket:\n{text}"
        );
        assert!(
            text.contains("le=\"0.00005\"} 0"),
            "and not in the 50us bucket:\n{text}"
        );
        assert!(text.contains("broker_http_request_duration_seconds_count{lane=\"public\",route=\"/session/refresh\"} 1"));
    }

    #[test]
    fn label_families_accumulate_independently() {
        let m = Metrics::new();
        m.record_authz("allow", "ok");
        m.record_authz("allow", "ok");
        m.record_authz("deny", "no_session");

        let text = m.render(&GaugeSnapshot::default());
        assert!(text.contains("broker_authz_decisions_total{decision=\"allow\",reason=\"ok\"} 2"));
        assert!(text
            .contains("broker_authz_decisions_total{decision=\"deny\",reason=\"no_session\"} 1"));
    }

    #[test]
    fn audit_drop_counter_is_exposed_because_it_is_the_alertable_one() {
        let m = Metrics::new();
        m.record_audit_dropped(17);
        let text = m.render(&GaugeSnapshot::default());
        assert!(text.contains("broker_audit_dropped_total 17"));
        assert!(
            text.contains("HOLE"),
            "the help text has to say what a nonzero value means; an operator \
             reading a scrape has no ADR in front of them"
        );
    }

    #[test]
    fn gauges_come_from_the_snapshot_not_from_maintained_counters() {
        let m = Metrics::new();
        let text = m.render(&GaugeSnapshot {
            sessions_live: 3,
            custody_dead: 1,
            log_level_override_active: true,
            ..GaugeSnapshot::default()
        });
        assert!(text.contains("broker_sessions_live 3"));
        assert!(text.contains("broker_custody{status=\"dead\"} 1"));
        assert!(text.contains("broker_log_level_override_active 1"));
    }
}
