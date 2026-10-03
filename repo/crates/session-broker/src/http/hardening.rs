//! Transport hardening applied to every listener: a body ceiling, a handler
//! deadline, and response headers that a JSON-only service should always send.
//!
//! None of this is business logic, and all of it fails the same way when it is
//! missing: nothing is wrong until something hostile or slow arrives. A client
//! that opens a request and never finishes it pins a task; a 2 MiB default body
//! limit is a thousand times what any endpoint here reads; a response without
//! `Cache-Control: no-store` can be replayed from a shared cache.
//!
//! ## Why the deadline skips the event stream
//!
//! `/session/events` is a long-lived SSE response by design (ADR-0013). A
//! handler deadline there would cut every healthy stream at the same instant
//! and the clients would reconnect in lock-step. The stream has its own
//! keep-alive and its own bound on subscriber lag, so it is exempt by path.

use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;

/// Paths that stream and so must not be given a handler deadline.
const STREAMING_PATHS: &[&str] = &["/session/events"];

#[derive(Debug, Clone)]
pub struct Hardening {
    /// Largest request body any endpoint will read. Every body this service
    /// accepts is a small JSON object or a form; a few KiB is already generous.
    pub max_body_bytes: usize,
    /// Wall-clock limit on a handler. `Duration::ZERO` disables it.
    pub request_timeout: Duration,
    /// Send `Strict-Transport-Security`. Only meaningful (and only legal to
    /// rely on) when the broker's own origin is HTTPS.
    pub hsts: bool,
}

impl Default for Hardening {
    fn default() -> Hardening {
        Hardening {
            max_body_bytes: 64 * 1024,
            request_timeout: Duration::from_secs(30),
            hsts: false,
        }
    }
}

/// Wrap `router` with the body limit, deadline and response headers.
///
/// Applied last, outside metrics instrumentation, so a request cut by the
/// deadline or refused for size still shows up as a status in the access
/// metrics rather than vanishing from them.
pub fn apply(router: Router, cfg: Hardening) -> Router {
    let timeout = cfg.request_timeout;
    let hsts = cfg.hsts;
    router
        .layer(DefaultBodyLimit::max(cfg.max_body_bytes))
        .layer(middleware::from_fn(move |req, next| {
            deadline(timeout, req, next)
        }))
        .layer(middleware::from_fn(move |req, next| {
            security_headers(hsts, req, next)
        }))
}

async fn deadline(timeout: Duration, req: Request<Body>, next: Next) -> Response {
    if timeout.is_zero() || STREAMING_PATHS.contains(&req.uri().path()) {
        return next.run(req).await;
    }
    match tokio::time::timeout(timeout, next.run(req)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":{"code":"timeout","message":"the request took too long"}}"#,
        )
            .into_response(),
    }
}

async fn security_headers(hsts: bool, req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // `no-store` unless a handler said otherwise: every response here is
    // per-user or per-moment, and none is safe to serve from a shared cache.
    set_if_absent(headers, header::CACHE_CONTROL, "no-store");
    set_if_absent(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_if_absent(headers, header::REFERRER_POLICY, "no-referrer");
    // The broker returns JSON and redirects, never a document. If one is ever
    // rendered in a frame or loads a subresource, that is an attack.
    set_if_absent(
        headers,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'",
    );
    set_if_absent(headers, header::X_FRAME_OPTIONS, "DENY");
    set_if_absent(
        headers,
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    if hsts {
        set_if_absent(
            headers,
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        );
    }
    response
}

fn set_if_absent(headers: &mut axum::http::HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    fn app(cfg: Hardening) -> Router {
        apply(
            Router::new()
                .route("/ok", get(|| async { "ok" }))
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        "late"
                    }),
                )
                .route(
                    "/session/events",
                    get(|| async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        "streamed"
                    }),
                )
                .route(
                    "/own-cache",
                    get(|| async { ([(header::CACHE_CONTROL, "max-age=5")], "x") }),
                )
                .route("/echo", post(|body: String| async move { body })),
            cfg,
        )
    }

    fn quick() -> Hardening {
        Hardening {
            request_timeout: Duration::from_millis(50),
            ..Hardening::default()
        }
    }

    async fn status(app: &Router, req: Request<Body>) -> StatusCode {
        app.clone().oneshot(req).await.unwrap().status()
    }

    fn get_req(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn a_slow_handler_is_cut_off_with_a_504() {
        assert_eq!(
            status(&app(quick()), get_req("/slow")).await,
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    #[tokio::test]
    async fn the_event_stream_is_exempt_from_the_deadline() {
        assert_eq!(
            status(&app(quick()), get_req("/session/events")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_zero_timeout_disables_the_deadline() {
        let cfg = Hardening {
            request_timeout: Duration::ZERO,
            ..Hardening::default()
        };
        assert_eq!(status(&app(cfg), get_req("/slow")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_and_a_small_one_passes() {
        let cfg = Hardening {
            max_body_bytes: 16,
            ..Hardening::default()
        };
        let app = app(cfg);
        let post_body = |n: usize| {
            Request::builder()
                .method("POST")
                .uri("/echo")
                .body(Body::from("x".repeat(n)))
                .unwrap()
        };
        assert_eq!(status(&app, post_body(8)).await, StatusCode::OK);
        assert_eq!(
            status(&app, post_body(64)).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn every_response_carries_the_hardening_headers() {
        let response = app(Hardening::default())
            .oneshot(get_req("/ok"))
            .await
            .unwrap();
        let h = response.headers();
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert!(h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        assert!(
            !h.contains_key(header::STRICT_TRANSPORT_SECURITY),
            "HSTS must not be sent unless the origin is https"
        );
    }

    #[tokio::test]
    async fn a_handlers_own_cache_control_is_not_overwritten() {
        let response = app(Hardening::default())
            .oneshot(get_req("/own-cache"))
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "max-age=5");
    }

    #[tokio::test]
    async fn hsts_is_sent_when_enabled() {
        let cfg = Hardening {
            hsts: true,
            ..Hardening::default()
        };
        let response = app(cfg).oneshot(get_req("/ok")).await.unwrap();
        assert!(response
            .headers()
            .contains_key(header::STRICT_TRANSPORT_SECURITY));
    }
}
