//! `GET /metrics` — Prometheus text exposition on the internal listener.
//!
//! ## Why it is here and not on the public listener
//!
//! Same reason `/admin/*` and `/internal/token` are: it is an operator surface.
//! It carries no identifiers (INV-12 — counts and latencies only, never a `sub`
//! or a `sid`), so the exposure if it leaked would be modest, but a scrape
//! endpoint on the browser-facing origin is a free source of traffic and timing
//! signal to anyone who asks for it.
//!
//! ## Why it is unauthenticated
//!
//! Scrape configs manage bearer tokens badly and rotating one silently breaks
//! monitoring, which is the thing that would have told you it broke. The
//! listener's network position is the control — the same posture ArrowRef takes
//! (its ADR-0015) and the same one that already guards the token-exchange lane
//! next door. If this listener is reachable from somewhere it should not be,
//! `/internal/token` is a far larger problem than the metrics.
//!
//! ## Gauges are sampled here, not maintained
//!
//! Session, generation and custody counts are read from the live map and the
//! store *at scrape time*. Mirroring them into atomics would put a write on
//! every session mutation to produce a number that can drift out of step with
//! the thing it describes; a value read once per scrape cannot.

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::response::{IntoResponse, Response};

use crate::audit::AuditSink;
use crate::http::events::SessionEvents;
use crate::http::internal::InternalState;
use crate::session::CustodyStatus;
use crate::store::repo;
use crate::telemetry::metrics::GaugeSnapshot;
use crate::telemetry::{LogControl, Metrics};

/// Everything `/metrics` needs that is not already in [`InternalState`].
#[derive(Clone)]
pub struct OpsState {
    pub metrics: Arc<Metrics>,
    pub events: Arc<SessionEvents>,
    pub log: Option<Arc<LogControl>>,
    pub audit: Option<AuditSink>,
    /// Handle to the writer thread, for the readiness probe.
    pub writer: Option<crate::store::writer::WriterHandle>,
    /// Set when shutdown begins, so `/readyz` fails and the load balancer stops
    /// sending new work while in-flight requests finish.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
}

/// `GET /readyz` — ready to take traffic, as distinct from `/healthz`, which
/// says only that the process is up.
///
/// Three things must hold: shutdown has not begun, the writer thread is still
/// receiving (otherwise every session mutation is being dropped on the floor),
/// and the read connection can answer a query. A broker failing any of them is
/// worse than absent — it accepts logins it cannot persist — so it reports
/// itself unready and lets the orchestrator route around it.
pub async fn readyz(
    State(internal): State<InternalState>,
    Extension(ops): Extension<OpsState>,
) -> Response {
    use axum::http::StatusCode;
    use std::sync::atomic::Ordering;

    let draining = ops.draining.load(Ordering::Relaxed);
    let writer_ok = ops.writer.as_ref().is_none_or(|w| w.is_alive());
    let store_ok = internal.reader.with(|conn| {
        conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .is_ok()
    });

    let ready = !draining && writer_ok && store_ok;
    let body = serde_json::json!({
        "ready": ready,
        "draining": draining,
        "writer": writer_ok,
        "store": store_ok,
    });
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        axum::Json(body),
    )
        .into_response()
}

pub async fn metrics(
    State(internal): State<InternalState>,
    Extension(ops): Extension<OpsState>,
) -> Response {
    let now = internal.clock.now();

    // One read pass for everything the store knows. A scrape that took three
    // separate reader locks would show three different instants of the same
    // system, which is how a graph ends up self-contradicting.
    let (custody, audit_rows, audit_oldest) = internal.reader.with(|conn| {
        let schedules = repo::live_custody_schedules(conn).unwrap_or_default();
        let stats = repo::audit_stats(conn).unwrap_or_default();
        (schedules, stats.rows, stats.oldest_at)
    });

    let mut snapshot = GaugeSnapshot {
        sessions_live: internal.sessions.len() as u64,
        generations_live: 0,
        event_subscribers: ops.events.subscribers() as u64,
        audit_rows: audit_rows.max(0) as u64,
        audit_oldest_seconds: audit_oldest
            .map(|t| (now.secs() - t.secs()).max(0) as u64)
            .unwrap_or(0),
        log_level_override_active: ops.log.as_ref().is_some_and(|l| l.override_active()),
        ..GaugeSnapshot::default()
    };

    for row in &custody {
        match row.status {
            CustodyStatus::Ok => snapshot.custody_ok += 1,
            CustodyStatus::Degraded => snapshot.custody_degraded += 1,
            // `live_custody_schedules` excludes dead grants — the worker stops
            // scheduling them — so this arm is unreachable today. Left explicit
            // rather than a catch-all so that if the query ever widens, the
            // gauge is already right instead of silently miscounting.
            CustodyStatus::Dead => snapshot.custody_dead += 1,
        }
    }

    if let Some(sink) = &ops.audit {
        ops.metrics.set_audit_queue_depth(sink.depth());
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        ops.metrics.render(&snapshot),
    )
        .into_response()
}
