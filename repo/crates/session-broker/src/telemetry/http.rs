//! Per-request instrumentation: one metrics observation and one log line.
//!
//! ## Why the matched route, never the path
//!
//! The label is `MatchedPath` — the axum pattern like `/admin/api-keys/{key_id}`
//! — for two reasons that point the same way. Cardinality is bounded by the
//! router rather than by the internet, and a raw path on this service carries
//! `?return_to=`, `?code=` and `?state=`, which INV-12 forbids anywhere near a
//! log line or a metric label.
//!
//! ## Why this is not a span
//!
//! One event per request, not an entered span, because `/authz` runs on every
//! request in the platform and span entry/exit is measurably more than an
//! atomic add. Targets are named (`broker::http`) so spans can be layered on
//! later without renaming anything an operator is already querying.
//!
//! ## The `&Request` trap
//!
//! `&axum::extract::Request` is not `Send` (its `Body` is not `Sync`), so
//! holding a reference to one across an await makes the middleware future
//! non-`Send` and the tower `Service` bound fails with an unreadable error.
//! Everything needed from the request is extracted into owned values *before*
//! `next.run(req)` is awaited.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;

use super::metrics::Metrics;

/// Wrap a router's requests in metrics + one log event.
///
/// `lane` is `public`, `internal` or `admin` — which listener answered, which is
/// the first thing an operator wants to know and the one thing the route alone
/// does not say.
///
/// Takes and returns the `Router` rather than handing back a layer, because
/// naming the type of a `from_fn` closure is worse than the problem it solves.
pub fn instrument_router(router: Router, lane: &'static str, metrics: Arc<Metrics>) -> Router {
    router.layer(axum::middleware::from_fn(move |req: Request, next: Next| {
        let metrics = metrics.clone();
        async move { instrument(lane, metrics, req, next).await }
    }))
}

async fn instrument(lane: &'static str, metrics: Arc<Metrics>, req: Request, next: Next) -> Response {
    // Owned before the await: see the module docs on the `&Request` trap.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        // A request that matched nothing is a 404. Bucketing them all under one
        // synthetic label is deliberate: the alternative is one series per
        // scanned URL, which is an unbounded cardinality hole an outsider can
        // widen at will.
        .unwrap_or_else(|| "<unmatched>".to_owned());
    let method = req.method().clone();

    let started = Instant::now();
    let response = next.run(req).await;
    let elapsed = started.elapsed();
    let status = response.status().as_u16();

    metrics.record_request(lane, &route, status, elapsed);

    // `debug` for the ordinary case and `warn` for 5xx: at `info` (the default
    // filter) this service would otherwise emit a line for every Envoy
    // ext_authz call in the platform, which is a lot of bytes to say "yes".
    if status >= 500 {
        tracing::warn!(
            target: "broker::http",
            lane, %method, route, status,
            elapsed_us = elapsed.as_micros() as u64,
            "request failed"
        );
    } else {
        tracing::debug!(
            target: "broker::http",
            lane, %method, route, status,
            elapsed_us = elapsed.as_micros() as u64,
            "request"
        );
    }

    response
}
