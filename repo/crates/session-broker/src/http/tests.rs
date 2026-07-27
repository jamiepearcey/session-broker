//! Contract tests, taken directly from the endpoint table in
//! `docs/architecture/implementation-strategy.md` §4.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt as _;

use super::*;
use crate::clock::{TestClock, Timestamp};
use crate::session::{CustodyId, SessionMap, SessionPolicy, Sid};

const T0: Timestamp = Timestamp(1_700_000_000);
const ORIGIN: &str = "https://app.example.com";

struct Harness {
    router: Router,
    clock: TestClock,
    sessions: Arc<SessionMap>,
}

impl Harness {
    fn new() -> Harness {
        Harness::with_policy(SessionPolicy::default())
    }

    fn with_policy(policy: SessionPolicy) -> Harness {
        let clock = TestClock::new(T0);
        let sessions = Arc::new(SessionMap::new(policy));
        let config = Arc::new(HttpConfig::new(ORIGIN, &policy).unwrap());
        let state = AppState {
            sessions: sessions.clone(),
            clock: Arc::new(clock.clone()),
            config: config.clone(),
            custody: None,
            audit: None,
            metrics: crate::telemetry::Metrics::new(),
        };
        Harness {
            router: router(state),
            clock,
            sessions,
        }
    }

    /// Establish a session and return the cookie value a browser would hold.
    fn login(&self) -> String {
        let issued = self.sessions.create(
            Sid("s1".into()),
            CustodyId("c1".into()),
            "user-42".into(),
            self.clock.now(),
        );
        issued.token.expose_for_cookie().to_owned()
    }

    async fn send(&self, request: Request<Body>) -> Response {
        self.router.clone().oneshot(request).await.unwrap()
    }
}

fn post(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("sec-fetch-site", "same-origin")
}

fn navigate(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("sec-fetch-site", "none")
        .header("sec-fetch-mode", "navigate")
}

fn with_session(builder: axum::http::request::Builder, token: &str) -> Request<Body> {
    builder
        .header("cookie", format!("__Host-broker_session={token}"))
        .body(Body::empty())
        .unwrap()
}

fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .collect()
}

async fn body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// --- cookie attributes (INV-1) --------------------------------------------

#[tokio::test]
async fn refresh_sets_a_hardened_session_cookie_and_a_readable_meta_cookie() {
    let h = Harness::new();
    let token = h.login();
    h.clock.advance(31);

    let response = h.send(with_session(post("/session/refresh"), &token)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(response.headers().contains_key("x-broker-handler-us"));

    let cookies = set_cookies(&response);
    let session = cookies
        .iter()
        .find(|c| c.starts_with("__Host-broker_session="))
        .expect("session cookie");
    assert!(session.contains("; Secure"));
    assert!(session.contains("; HttpOnly"));
    assert!(session.contains("; SameSite=Lax"));
    assert!(session.contains("; Path=/"));
    assert!(!session.contains("Domain="), "__Host- forbids Domain");

    let meta = cookies
        .iter()
        .find(|c| c.starts_with("broker_meta="))
        .expect("meta cookie");
    // INV-9: the client must be able to read this one.
    assert!(!meta.contains("HttpOnly"));

    let encoded = meta
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("broker_meta=");
    let decoded = decode_meta(encoded).expect("meta decodes");
    assert_eq!(decoded.gen, 2);
    assert_eq!(decoded.sub, "user-42");
}

// --- CSRF (INV-2) ----------------------------------------------------------

#[tokio::test]
async fn a_cross_site_refresh_is_rejected_before_any_state_changes() {
    let h = Harness::new();
    let token = h.login();
    h.clock.advance(31);

    let request = Request::builder()
        .method("POST")
        .uri("/session/refresh")
        .header("sec-fetch-site", "cross-site")
        .header("cookie", format!("__Host-broker_session={token}"))
        .body(Body::empty())
        .unwrap();

    let response = h.send(request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["error"], "csrf_rejected");

    // The session must be untouched: still generation 1, no rotation happened.
    assert_eq!(
        h.sessions
            .meta_for(&crate::token::TokenHash::of(&token))
            .unwrap()
            .gen,
        1
    );
}

#[tokio::test]
async fn logout_is_csrf_protected_too() {
    let h = Harness::new();
    let token = h.login();
    let request = Request::builder()
        .method("POST")
        .uri("/logout")
        .header("sec-fetch-site", "cross-site")
        .header("cookie", format!("__Host-broker_session={token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(request).await.status(), StatusCode::FORBIDDEN);
}

// --- the state table -------------------------------------------------------

#[tokio::test]
async fn no_cookie_yields_invalid_session_with_a_login_url() {
    let h = Harness::new();
    let response = h
        .send(post("/session/refresh").body(Body::empty()).unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = body_json(response).await;
    assert_eq!(body["error"], "invalid_session");
    assert_eq!(body["login_url"], format!("{ORIGIN}/auth/login"));
}

#[tokio::test]
async fn a_stale_session_refreshes_locally() {
    let h = Harness::new();
    let token = h.login();
    // Past gen_ttl: resource access would be refused, but refresh must work.
    h.clock.advance(601);

    let response = h.send(with_session(post("/session/refresh"), &token)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["gen"], 2);
}

#[tokio::test]
async fn an_expired_session_is_refused_and_told_where_to_log_in() {
    let policy = SessionPolicy {
        idle_ttl_secs: 100,
        absolute_ttl_secs: 200,
        ..SessionPolicy::default()
    };
    let h = Harness::with_policy(policy);
    let token = h.login();
    h.clock.advance(101);

    let response = h.send(with_session(post("/session/refresh"), &token)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["error"], "session_expired");
    assert!(body["login_url"].as_str().unwrap().starts_with(ORIGIN));
}

#[tokio::test]
async fn get_session_introspects_without_rotating() {
    let h = Harness::new();
    let token = h.login();

    let request = Request::builder()
        .method("GET")
        .uri("/session")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("__Host-broker_session={token}"))
        .body(Body::empty())
        .unwrap();
    let response = h.send(request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        set_cookies(&response).is_empty(),
        "introspection must not set cookies"
    );
    assert_eq!(body_json(response).await["gen"], 1);
}

// --- the interactive argument ---------------------------------------------

#[tokio::test]
async fn interactive_refresh_redirects_a_dead_session_to_the_idp() {
    let policy = SessionPolicy {
        idle_ttl_secs: 100,
        absolute_ttl_secs: 200,
        ..SessionPolicy::default()
    };
    let h = Harness::with_policy(policy);
    let token = h.login();
    h.clock.advance(101);

    let response = h
        .send(with_session(
            navigate("/session/refresh?interactive=1&return_to=/dashboard"),
            &token,
        ))
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        // `/` is a legal query character (RFC 3986 pchar) and is left readable;
        // `?` and `#` are escaped.
        &format!("{ORIGIN}/auth/login?return_to=/dashboard")[..]
    );
    // The dead cookies are cleared on the way out.
    assert!(set_cookies(&response)
        .iter()
        .any(|c| c.contains("Max-Age=0")));
}

#[tokio::test]
async fn interactive_refresh_of_a_live_session_just_goes_back_to_the_app() {
    let h = Harness::new();
    let token = h.login();
    h.clock.advance(31);

    let response = h
        .send(with_session(
            navigate("/session/refresh?interactive=1&return_to=/dashboard"),
            &token,
        ))
        .await;

    // `interactive` is ignored when the session is fine: there is nothing to
    // log into, so it refreshes locally and returns.
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/dashboard"
    );
    assert!(set_cookies(&response)
        .iter()
        .any(|c| c.starts_with("__Host-broker_session=")));
}

#[tokio::test]
async fn a_dead_session_without_interactive_gets_an_error_not_a_redirect() {
    let policy = SessionPolicy {
        idle_ttl_secs: 100,
        absolute_ttl_secs: 200,
        ..SessionPolicy::default()
    };
    let h = Harness::with_policy(policy);
    let token = h.login();
    h.clock.advance(101);

    let response = h
        .send(with_session(navigate("/session/refresh"), &token))
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_get_form_refuses_non_navigation_requests() {
    let h = Harness::new();
    let token = h.login();

    let request = Request::builder()
        .method("GET")
        .uri("/session/refresh?interactive=1")
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header("cookie", format!("__Host-broker_session={token}"))
        .body(Body::empty())
        .unwrap();

    assert_eq!(h.send(request).await.status(), StatusCode::BAD_REQUEST);
}

// --- INV-4: no open redirect ----------------------------------------------

#[tokio::test]
async fn a_hostile_return_to_is_dropped_not_followed() {
    let h = Harness::new();
    let token = h.login();
    h.clock.advance(31);

    let response = h
        .send(with_session(
            navigate("/session/refresh?return_to=//evil.example.com"),
            &token,
        ))
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
}

// --- logout (INV-7) --------------------------------------------------------

#[tokio::test]
async fn logout_clears_cookies_kills_the_session_and_is_idempotent() {
    let h = Harness::new();
    let token = h.login();

    let response = h.send(with_session(post("/logout"), &token)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cleared = set_cookies(&response);
    assert_eq!(cleared.len(), 2);
    assert!(cleared.iter().all(|c| c.contains("Max-Age=0")));

    // Every generation died with it.
    let response = h.send(with_session(post("/session/refresh"), &token)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "session_expired");

    // Logging out again is still a 200.
    let response = h.send(with_session(post("/logout"), &token)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

// --- config validation -----------------------------------------------------

#[test]
fn plaintext_base_urls_are_refused_off_loopback() {
    let policy = SessionPolicy::default();
    assert_eq!(
        HttpConfig::new("http://app.example.com", &policy).unwrap_err(),
        HttpConfigError::InsecureOffLoopback("http://app.example.com".into())
    );
    assert!(HttpConfig::new("http://localhost:5173", &policy).is_ok());
    assert!(HttpConfig::new("https://app.example.com", &policy).is_ok());
    assert!(HttpConfig::new("app.example.com", &policy).is_err());
}

#[test]
fn dev_mode_drops_the_host_prefix_that_would_require_secure() {
    let policy = SessionPolicy::default();
    let dev = HttpConfig::new("http://localhost:5173", &policy).unwrap();
    assert_eq!(dev.session_cookie_name(), "broker_session");
    let prod = HttpConfig::new("https://app.example.com", &policy).unwrap();
    assert_eq!(prod.session_cookie_name(), "__Host-broker_session");
}
