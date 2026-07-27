//! `ANY /authz/*` — the edge authorization check (Envoy `ext_authz`).
//!
//! This is the gateway's per-request question: *is this request carrying a live
//! session, and if so, whose?* A `200` means allow and carries the caller's
//! identity in response headers, which Envoy copies onto the upstream request.
//! Anything else means deny, and Envoy never forwards the request at all.
//!
//! ## Why this exists alongside `/internal/token`
//!
//! They answer different questions and neither subsumes the other:
//!
//! * `/internal/token` — "give me the **upstream access token** for this
//!   session", so a backend can call a third-party API as the user. It returns
//!   a secret, and is therefore dual-authenticated (INV-11).
//! * `/authz` — "may this request proceed, and **who is it**?" It returns no
//!   secret at all: a subject and a custody status, both of which the user's own
//!   browser already knows from the meta cookie.
//!
//! Collapsing them would mean the edge holds a credential that can mint upstream
//! tokens for every user, on the request path, purely to learn a subject.
//!
//! ## The header-forgery hazard, stated plainly
//!
//! Everything downstream of the gateway trusts `x-broker-subject`. That is only
//! safe if two things hold, and **neither is enforceable from inside this
//! module**:
//!
//! 1. The gateway **strips** any client-supplied `x-broker-*` header before it
//!    runs this check. Otherwise a caller simply sends the header themselves and
//!    the edge passes it straight through — the identity-header spoof, rebuilt.
//! 2. Services are reachable **only** through the gateway. A service on a public
//!    port that trusts an identity header is worse than no auth at all, because
//!    it looks authenticated.
//!
//! Both are deployment properties. `deploy/envoy.yaml` does (1) explicitly and
//! comments say so; (2) is a bind-address and network-policy decision. This
//! module's job is to be correct given them, and to make sure the requirement is
//! impossible to miss when reading the code.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;

use super::internal::InternalState;
use crate::session::CustodyStatus;
use crate::token::TokenHash;

/// Who the request is. Downstream services read this and nothing else.
const SUBJECT_HEADER: &str = "x-broker-subject";
/// Health of the upstream grant behind the session — so a service can tell
/// "this user is signed in but their upstream token is dead" without a second
/// call to anyone.
const CUSTODY_HEADER: &str = "x-broker-custody";

pub fn router(state: InternalState) -> Router {
    // A wildcard, because Envoy's HTTP `ext_authz` calls
    // `{path_prefix}{original_path}` — the check has to answer for every path
    // the gateway fronts, not one fixed route.
    //
    // All THREE routes are needed. `/{*path}` does not match an empty segment,
    // so a request to the app root (`/`) arrives here as `/authz/` and would
    // 404 without the middle one. A 404 from this endpoint is a **deny**, so
    // that gap would fail the site's root closed and look exactly like an auth
    // outage. Its own test covers it.
    Router::new()
        .route("/authz", axum::routing::any(check))
        .route("/authz/", axum::routing::any(check))
        .route("/authz/{*path}", axum::routing::any(check))
        .with_state(state)
}

async fn check(State(state): State<InternalState>, headers: HeaderMap) -> Response {
    // Metrics only, allow and deny alike — never an audit row (ADR-0015).
    //
    // This handler runs on EVERY request the edge fronts. A store write here
    // would put a disk write on the platform's request path to produce a record
    // of a request that changed nothing, which is both the latency problem and
    // the wrong record. A denial is a counter plus one log line; a denial storm
    // is an alert, not a table scan.
    let decide = |decision: &str, reason: &str| {
        state.metrics.record_authz(decision, reason);
    };
    // The gateway authenticates as a backend, exactly like any other consumer of
    // the internal lane: it holds an issued API key, which means it appears in
    // the console's key list and can be revoked there if the edge is ever
    // compromised. An unauthenticated authz endpoint would let anyone ask the
    // broker to resolve a stolen cookie into a subject.
    if !super::internal::backend_is_authenticated(&state, &headers) {
        decide("deny", "edge_unauthenticated");
        tracing::warn!(
            target: "broker::authz",
            reason = "edge_unauthenticated",
            "authz called by something holding no backend credential"
        );
        return (StatusCode::FORBIDDEN, "edge is not authenticated").into_response();
    }

    let Some(cookie_header) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        decide("deny", "no_cookie");
        return deny("no cookie");
    };

    let Some(token) = session_cookie(cookie_header) else {
        decide("deny", "no_session_cookie");
        return deny("no session cookie");
    };

    let now = state.clock.now();
    let hash = TokenHash::of(token);

    // `authenticates()` is `Active` only — a stale-but-refreshable generation
    // does NOT pass the gate. The browser must refresh first, so a tab that has
    // been asleep cannot keep driving services on a generation it never renewed.
    if !state.sessions.resolve(&hash, now).authenticates() {
        decide("deny", "session_not_active");
        return deny("session not active");
    }

    let Some(meta) = state.sessions.meta_for(&hash) else {
        decide("deny", "session_not_active");
        return deny("session not active");
    };

    // A dead upstream grant is NOT a failed authorization. Under the `degrade`
    // policy the session is deliberately still valid for broker-local auth; it
    // is only calls to the upstream API that cannot work. Refusing here would
    // silently convert that policy into `kill`.
    let custody = match meta.custody {
        CustodyStatus::Ok => "ok",
        CustodyStatus::Degraded => "degraded",
        CustodyStatus::Dead => "dead",
    };

    decide("allow", custody);
    let mut response = StatusCode::OK.into_response();
    let out = response.headers_mut();
    if let (Ok(name), Ok(value)) = (
        HeaderName::try_from(SUBJECT_HEADER),
        HeaderValue::from_str(&meta.sub),
    ) {
        out.insert(name, value);
    } else {
        // A subject that cannot be expressed as a header value would otherwise
        // allow the request with NO identity attached, which downstream would
        // read as anonymous-but-authorized. Refuse instead.
        decide("deny", "subject_not_header_safe");
        return deny("subject is not header-safe");
    }
    if let (Ok(name), Ok(value)) = (
        HeaderName::try_from(CUSTODY_HEADER),
        HeaderValue::from_str(custody),
    ) {
        out.insert(name, value);
    }
    response
}

/// Deny with a reason the gateway logs but never forwards to the caller.
///
/// 401 rather than 403: the caller can fix this by signing in, and the SPA's
/// interceptor keys off 401 to trigger a refresh.
fn deny(reason: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, reason).into_response()
}

/// Both cookie names, because the broker drops the `__Host-` prefix over
/// loopback (the prefix mandates `Secure`, which plain-HTTP dev cannot satisfy).
/// Recognising only the hardened name would work in production and reject every
/// request in development.
fn session_cookie(cookie_header: &str) -> Option<&str> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        for name in ["__Host-broker_session", "broker_session"] {
            if let Some(value) = part.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{TestClock, Timestamp};
    use crate::session::{CustodyId, SessionMap, SessionPolicy, Sid};
    use crate::store::Reader;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    const T0: Timestamp = Timestamp(1_700_000_000);
    const EDGE_KEY: &str = "an-edge-key-that-is-at-least-32-chars-xx";

    fn harness() -> (Router, String) {
        let conn = crate::store::open_in_memory().unwrap();
        let sessions = Arc::new(SessionMap::new(SessionPolicy::default()));
        let issued = sessions.create(
            Sid("sid-1".to_owned()),
            CustodyId("cust-1".to_owned()),
            "alice".to_owned(),
            T0,
        );
        let state = InternalState {
            sessions,
            reader: Arc::new(Reader::new(conn)),
            clock: Arc::new(TestClock::new(T0)),
            api_key: Some(Arc::from(EDGE_KEY)),
            writer: None,
            last_touch: Default::default(),
            metrics: crate::telemetry::Metrics::new(),
            audit: None,
        };
        (router(state), issued.token.expose_for_cookie().to_owned())
    }

    fn request(path: &str, cookie: Option<&str>, key: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method("GET").uri(path);
        if let Some(c) = cookie {
            b = b.header("cookie", format!("broker_session={c}"));
        }
        if let Some(k) = key {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn a_live_session_is_allowed_and_carries_its_subject() {
        let (router, token) = harness();
        let response = router
            .oneshot(request("/authz/api/runs", Some(&token), Some(EDGE_KEY)))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(SUBJECT_HEADER).unwrap(),
            "alice",
            "the gateway must learn who the caller is, or downstream cannot attribute anything"
        );
        assert_eq!(response.headers().get(CUSTODY_HEADER).unwrap(), "ok");
    }

    /// The wildcard matters: Envoy calls `{path_prefix}{original_path}`, so the
    /// check has to answer for every path the gateway fronts. A router that only
    /// matched `/authz` would 404 — and a 404 is a DENY, so every request in the
    /// deployment would fail closed and look like an auth outage.
    #[tokio::test]
    async fn it_answers_for_any_forwarded_path() {
        let (router, token) = harness();
        for path in [
            "/authz",
            "/authz/",
            "/authz/oms/commands",
            "/authz/l2/objects/abc",
        ] {
            let response = router
                .clone()
                .oneshot(request(path, Some(&token), Some(EDGE_KEY)))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "path {path} must resolve"
            );
        }
    }

    #[tokio::test]
    async fn no_session_is_denied() {
        let (router, _) = harness();
        let response = router
            .oneshot(request("/authz/api/runs", None, Some(EDGE_KEY)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_forged_cookie_is_denied() {
        let (router, _) = harness();
        let response = router
            .oneshot(request(
                "/authz/api/runs",
                Some("not-a-real-token"),
                Some(EDGE_KEY),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The edge is a backend like any other. An unauthenticated authz endpoint
    /// would let anyone ask the broker to resolve a stolen cookie into a subject.
    #[tokio::test]
    async fn an_unauthenticated_edge_is_refused() {
        let (router, token) = harness();
        let response = router
            .clone()
            .oneshot(request("/authz/api/runs", Some(&token), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let wrong = router
            .oneshot(request("/authz/api/runs", Some(&token), Some("wrong-key")))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    }
}
