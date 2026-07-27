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
