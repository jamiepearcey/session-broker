//! Tests for `POST /session/token`.
//!
//! Sessions are made in the same `SessionMap` the route reads and grants are
//! made through the admin routes, so each test crosses the lanes the way a
//! deployment does. Tokens are checked by `jsonwebtoken` against the keys the
//! broker serves, and every statement about a row is read through a separate
//! connection after the writer has flushed.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt as _;

use crate::audit::{action, AuditConfig, AuditSink};
use crate::clock::{Clock, TestClock, Timestamp};
use crate::config::IssuerConfig;
use crate::http::admin::AdminState;
use crate::http::{hardening, AppState, HttpConfig};
use crate::issuer::{bootstrap, IssuerHandle, KeyPolicy};
use crate::session::{CustodyId, SessionMap, SessionPolicy, Sid};
use crate::store::repo::{self, AuditQuery, StoredAuditRow};
use crate::store::writer::{AdminWrite, Writer};
use crate::store::Reader;
use crate::telemetry::Metrics;

const T0: Timestamp = Timestamp(1_700_000_000);
const ISSUER: &str = "https://broker.example.com";
const ADMIN_KEY: &str = "an-admin-key-that-is-at-least-32-chars";

struct Harness {
    /// The public router, hardened as `main` hardens it.
    app: Router,
    admin: Router,
    clock: TestClock,
    sessions: Arc<SessionMap>,
    metrics: Arc<Metrics>,
    path: std::path::PathBuf,
    writer: Writer,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
        let _ = std::fs::remove_file(self.path.with_extension("key"));
    }
}

fn issuer_config(default_tenant: Option<&str>) -> IssuerConfig {
    IssuerConfig {
        issuer: ISSUER.to_owned(),
        audiences: vec!["logless".to_owned()],
        machine_ttl_secs: 86_400,
        user_ttl_secs: 3_600,
        max_ttl_secs: 2_592_000,
        publish_lead_secs: 86_400,
        jwks_max_age_secs: 300,
        jwks_uri: format!("{ISSUER}/auth/jwks.json"),
        token_endpoint: format!("{ISSUER}/auth/token"),
        default_user_tenant: default_tenant.map(str::to_owned),
        default_user_roles: vec!["viewer".to_owned()],
    }
}

/// `default_tenant`: the install's `default_user_tenant`. `configured: false`
/// leaves the issuer off.
fn harness_with(
    tag: &str,
    configured: bool,
    default_tenant: Option<&str>,
    policy: SessionPolicy,
) -> Harness {
    let path = std::env::temp_dir().join(format!(
        "session-broker-usertoken-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let keyfile = path.with_extension("key");
    let writer = Writer::spawn(crate::store::open(&path, &keyfile).unwrap());
    let reader = Arc::new(Reader::new(crate::store::open(&path, &keyfile).unwrap()));
    let test_clock = TestClock::new(T0);
    let clock: Arc<dyn Clock> = Arc::new(test_clock.clone());
    let metrics = Metrics::new();
    let audit = AuditSink::new(writer.handle(), metrics.clone(), AuditConfig::default());

    let signer = configured.then(|| {
        bootstrap(
            reader.clone(),
            writer.handle(),
            Some(audit.clone()),
            clock.clone(),
            KeyPolicy::default(),
        )
        .unwrap()
    });
    let sessions = Arc::new(SessionMap::new(policy));
    let state = AppState {
        sessions: sessions.clone(),
        clock: clock.clone(),
        config: Arc::new(HttpConfig::new(ISSUER, &policy).unwrap()),
        custody: None,
        audit: Some(audit.clone()),
        metrics: metrics.clone(),
        rate_limit: None,
        issuer: signer.clone().map(|signer| IssuerHandle {
            signer,
            config: Arc::new(issuer_config(default_tenant)),
            client_failures: None,
        }),
    };
    let admin = crate::http::admin::router(AdminState {
        sessions: sessions.clone(),
        reader,
        writer: writer.handle(),
        clock,
        admin_key: Some(Arc::from(ADMIN_KEY)),
        audit: Some(audit),
        log: None,
        metrics: metrics.clone(),
        rate_limit: None,
        issuer: signer,
    });
    Harness {
        app: hardening::apply(crate::http::router(state), hardening::Hardening::default()),
        admin,
        clock: test_clock,
        sessions,
        metrics,
        path,
        writer,
    }
}

fn harness(tag: &str) -> Harness {
    harness_with(tag, true, None, SessionPolicy::default())
}

impl Harness {
    async fn admin(&self, method: &str, uri: &str, body: Option<serde_json::Value>) -> StatusCode {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {ADMIN_KEY}"));
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
        self.admin
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
            .status()
    }

    async fn grant(&self, sub: &str, tenant: &str, roles: &[&str], indexes: &[&str]) {
        let status = self
            .admin(
                "POST",
                "/admin/user-grants",
                Some(serde_json::json!({
                    "sub": sub, "tenant": tenant, "roles": roles, "indexes": indexes,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    /// A signed-in session for `sub`: the cookie value a browser holds, and
    /// the broker's own id for it.
    fn login(&self, sub: &str) -> (String, String) {
        let sid = format!("sid-{sub}");
        let issued = self.sessions.create(
            Sid(sid.clone()),
            CustodyId(format!("custody-{sub}")),
            sub.to_owned(),
            self.clock.now(),
        );
        (issued.token.expose_for_cookie().to_owned(), sid)
    }

    /// The browser's request: same-origin, with the session cookie.
    async fn mint(&self, cookie: &str, body: serde_json::Value) -> Response {
        self.send(
            Request::builder()
                .method("POST")
                .uri("/session/token")
                .header("sec-fetch-site", "same-origin")
                .header(header::COOKIE, format!("__Host-broker_session={cookie}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn send(&self, request: Request<Body>) -> Response {
        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Wait for the writer to commit everything enqueued so far.
    fn flush(&self) {
        self.writer
            .handle()
            .write_admin(AdminWrite::RevokeApiKey {
                key_id: "flush".to_owned(),
                now: T0,
            })
            .unwrap();
    }

    /// A connection of the test's own, so what it sees is what committed.
    fn connect(&self) -> rusqlite::Connection {
        crate::store::open(&self.path, &self.path.with_extension("key")).unwrap()
    }

    /// Newest first.
    fn audit(&self, action: &str) -> Vec<StoredAuditRow> {
        self.flush();
        repo::list_audit(
            &self.connect(),
            &AuditQuery {
                limit: 1000,
                ..AuditQuery::default()
            },
        )
        .unwrap()
        .into_iter()
        .filter(|r| r.row.action == action)
        .collect()
    }

    /// Verify with an independent decoder against the keys the broker serves.
    /// `exp` is checked by the caller: the broker runs on a test clock, the
    /// decoder on the wall clock.
    async fn verify(&self, token: &str) -> (jsonwebtoken::Header, serde_json::Value) {
        let response = self
            .send(
                Request::builder()
                    .uri("/auth/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(json(response).await).unwrap();
        let header = jsonwebtoken::decode_header(token).unwrap();
        let jwk = set
            .find(header.kid.as_deref().unwrap())
            .expect("kid is served");
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_audience(&["logless"]);
        validation.set_issuer(&[ISSUER]);
        validation.validate_exp = false;
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation).expect("verifies");
        (decoded.header, decoded.claims)
    }
}

async fn json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn granted(response: Response) -> serde_json::Value {
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// A refusal's status and its `error` code.
async fn refused(response: Response) -> (StatusCode, String) {
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = json(response).await;
    assert!(body["detail"].is_string(), "{body}");
    (status, body["error"].as_str().unwrap().to_owned())
}

fn audience() -> serde_json::Value {
    serde_json::json!({ "audience": "logless" })
}

// --- the guards ------------------------------------------------------------

#[tokio::test]
async fn it_is_refused_without_the_same_origin_signal_before_anything_is_looked_up() {
    let h = harness("csrf");
    h.grant("user-1", "acme", &["admin"], &["main"]).await;
    let (cookie, _) = h.login("user-1");
    let request = |fetch_site: Option<&str>, origin: Option<&str>| {
        let mut b = Request::builder()
            .method("POST")
            .uri("/session/token")
            .header(header::COOKIE, format!("__Host-broker_session={cookie}"));
        if let Some(v) = fetch_site {
            b = b.header("sec-fetch-site", v);
        }
        if let Some(v) = origin {
            b = b.header(header::ORIGIN, v);
        }
        b.body(Body::from(audience().to_string())).unwrap()
    };

    // A valid cookie and a valid body, with no signal, a cross-site one, and a
    // foreign Origin: all refused.
    for (site, origin) in [
        (None, None),
        (Some("cross-site"), None),
        (Some("same-site"), None),
        (Some("none"), None),
        (None, Some("https://evil.example.com")),
    ] {
        assert_eq!(
            refused(h.send(request(site, origin)).await).await,
            (StatusCode::FORBIDDEN, "csrf_rejected".to_owned()),
            "{site:?} {origin:?}"
        );
    }
    // The Origin fallback accepts the broker's own origin.
    granted(h.send(request(None, Some(ISSUER))).await).await;
    // Nothing was recorded for the refused ones: the guard ran before the
    // session was even resolved.
    assert!(h.audit(action::TOKEN_ISSUANCE_REFUSED).is_empty());
}

#[tokio::test]
async fn no_cookie_is_401_and_an_unknown_cookie_is_401() {
    let h = harness("nocookie");
    let bare = Request::builder()
        .method("POST")
        .uri("/session/token")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(audience().to_string()))
        .unwrap();
    assert_eq!(
        refused(h.send(bare).await).await,
        (StatusCode::UNAUTHORIZED, "invalid_session".to_owned())
    );
    assert_eq!(
        refused(h.mint("not-a-session-cookie", audience()).await).await,
        (StatusCode::UNAUTHORIZED, "invalid_session".to_owned())
    );
    // The 401 carries the login URL, like every other session refusal.
    let response = h.mint("nope", audience()).await;
    assert!(json(response).await["login_url"]
        .as_str()
        .unwrap()
        .starts_with(ISSUER));
}

#[tokio::test]
async fn an_expired_revoked_or_stale_session_is_refused_exactly_like_authz() {
    let policy = SessionPolicy {
        idle_ttl_secs: 1800,
        ..SessionPolicy::default()
    };
    let h = harness_with("dead", true, Some("default"), policy);

    // Idle expiry: a clock-driven pair around the boundary.
    let (cookie, _) = h.login("idle-user");
    h.clock.advance(599);
    granted(h.mint(&cookie, audience()).await).await;
    // The newest generation ages out at 600: refreshable, but not Active.
    h.clock.advance(2);
    assert_eq!(
        refused(h.mint(&cookie, audience()).await).await,
        (StatusCode::UNAUTHORIZED, "session_stale".to_owned())
    );
    h.clock.advance(1800);
    assert_eq!(
        refused(h.mint(&cookie, audience()).await).await,
        (StatusCode::UNAUTHORIZED, "session_expired".to_owned())
    );

    // Logout.
    let (cookie, sid) = h.login("gone-user");
    granted(h.mint(&cookie, audience()).await).await;
    assert!(h.sessions.tombstone_session(&Sid(sid), h.clock.now()));
    assert_eq!(
        refused(h.mint(&cookie, audience()).await).await,
        (StatusCode::UNAUTHORIZED, "session_expired".to_owned())
    );
}

// --- what is signed --------------------------------------------------------

#[tokio::test]
async fn a_granted_user_gets_a_token_whose_claims_come_from_the_grant_table() {
    let h = harness("claims");
    h.grant("user-1", "acme", &["admin", "writer"], &["main", "audit"])
        .await;
    let (cookie, sid) = h.login("user-1");

    // The request's own `tenant` is not a way to widen anything.
    let response = h.mint(&cookie, audience()).await;
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        "no-cache",
        "a token is not cacheable"
    );
    let body = granted(response).await;
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3_600);
    assert_eq!(body["tenant"], "acme");
    assert_eq!(body["roles"], serde_json::json!(["admin", "writer"]));
    assert_eq!(body["indexes"], serde_json::json!(["main", "audit"]));

    let token = body["access_token"].as_str().unwrap();
    let (header, claims) = h.verify(token).await;
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], "logless");
    assert_eq!(claims["sub"], "user-1");
    assert_eq!(claims["sid"], sid.as_str());
    assert_ne!(claims["sid"], cookie.as_str(), "the sid, never the cookie");
    assert_eq!(claims["kind"], "user");
    assert_eq!(claims["tenant"], "acme");
    assert_eq!(claims["roles"], serde_json::json!(["admin", "writer"]));
    assert_eq!(claims["indexes"], serde_json::json!(["main", "audit"]));
    assert_eq!(claims["iat"], T0.secs());
    assert_eq!(claims["exp"], T0.secs() + 3_600);
    assert_eq!(claims["jti"].as_str().unwrap().len(), 22);
    assert!(claims.get("nbf").is_none());
    assert!(!token.contains(&cookie));

    // Two tokens, two jtis.
    let again = granted(h.mint(&cookie, audience()).await).await;
    let (_, again) = h.verify(again["access_token"].as_str().unwrap()).await;
    assert_ne!(again["jti"], claims["jti"]);
}

#[tokio::test]
async fn the_expiry_is_capped_at_the_sessions_idle_expiry() {
    let policy = SessionPolicy {
        idle_ttl_secs: 1800,
        ..SessionPolicy::default()
    };
    let h = harness_with("cap", true, None, policy);
    h.grant("user-1", "acme", &["viewer"], &["*"]).await;
    let (cookie, _) = h.login("user-1");

    // Idle expiry is T0 + 1800; the ordinary lifetime is 3600.
    h.clock.advance(100);
    let body = granted(h.mint(&cookie, audience()).await).await;
    assert_eq!(body["expires_in"], 1_700);
    let (_, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims["exp"], T0.secs() + 1_800);

    // A session whose idle window is longer than the lifetime is not capped.
    let long = harness("nocap");
    long.grant("user-1", "acme", &["viewer"], &["*"]).await;
    let (cookie, _) = long.login("user-1");
    let body = granted(long.mint(&cookie, audience()).await).await;
    assert_eq!(body["expires_in"], 3_600);
}

#[tokio::test]
async fn an_unknown_audience_or_a_bad_body_is_400() {
    let h = harness("audience");
    h.grant("user-1", "acme", &["viewer"], &["*"]).await;
    let (cookie, _) = h.login("user-1");
    for body in [
        serde_json::json!({ "audience": "someone-else" }),
        serde_json::json!({ "audience": "" }),
    ] {
        assert_eq!(
            refused(h.mint(&cookie, body).await).await,
            (StatusCode::BAD_REQUEST, "bad_audience".to_owned())
        );
    }
    for body in [
        serde_json::json!({}),
        serde_json::json!({ "tenant": "acme" }),
        serde_json::json!("logless"),
    ] {
        assert_eq!(
            refused(h.mint(&cookie, body).await).await,
            (StatusCode::BAD_REQUEST, "bad_request".to_owned())
        );
    }
    let raw = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/session/token")
                .header("sec-fetch-site", "same-origin")
                .header(header::COOKIE, format!("__Host-broker_session={cookie}"))
                .body(Body::from("audience=logless"))
                .unwrap(),
        )
        .await;
    assert_eq!(
        refused(raw).await,
        (StatusCode::BAD_REQUEST, "bad_request".to_owned())
    );
}

// --- which grant -----------------------------------------------------------

#[tokio::test]
async fn several_grants_need_a_tenant_and_a_tenant_without_a_grant_is_403() {
    let h = harness("several");
    h.grant("user-1", "acme", &["admin"], &["main"]).await;
    h.grant("user-1", "globex", &["viewer"], &["*"]).await;
    let (cookie, _) = h.login("user-1");

    assert_eq!(
        refused(h.mint(&cookie, audience()).await).await,
        (StatusCode::BAD_REQUEST, "bad_request".to_owned())
    );
    let body = granted(
        h.mint(
            &cookie,
            serde_json::json!({ "audience": "logless", "tenant": "globex" }),
        )
        .await,
    )
    .await;
    assert_eq!(body["tenant"], "globex");
    assert_eq!(body["roles"], serde_json::json!(["viewer"]));
    assert_eq!(body["indexes"], serde_json::json!(["*"]));

    // A tenant that exists but where this user has no grant.
    h.grant("someone-else", "initech", &["admin"], &["*"]).await;
    assert_eq!(
        refused(
            h.mint(
                &cookie,
                serde_json::json!({ "audience": "logless", "tenant": "initech" }),
            )
            .await
        )
        .await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );
}

#[tokio::test]
async fn one_grant_needs_no_tenant_and_a_revoked_or_disabled_one_does_not_count() {
    let h = harness("states");
    h.grant("user-1", "acme", &["viewer"], &["*"]).await;
    let (cookie, _) = h.login("user-1");
    let ask = || serde_json::json!({ "audience": "logless" });

    // Matches: one live grant.
    assert_eq!(
        granted(h.mint(&cookie, ask()).await).await["tenant"],
        "acme"
    );

    // Does not match: the grant revoked.
    assert_eq!(
        h.admin("DELETE", "/admin/user-grants/user-1/acme", None)
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        refused(h.mint(&cookie, ask()).await).await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );

    // Matches again: a revoked grant created again is live again.
    h.grant("user-1", "acme", &["editor"], &["*"]).await;
    assert_eq!(
        granted(h.mint(&cookie, ask()).await).await["roles"],
        serde_json::json!(["editor"])
    );

    // Does not match: the tenant disabled.
    assert_eq!(
        h.admin("DELETE", "/admin/tenants/acme", None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        refused(h.mint(&cookie, ask()).await).await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );
}

#[tokio::test]
async fn a_user_with_no_grant_is_refused_unless_the_install_has_a_default_tenant() {
    // No default: no grant is 403.
    let strict = harness("strict");
    let (cookie, _) = strict.login("stranger");
    assert_eq!(
        refused(strict.mint(&cookie, audience()).await).await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );

    // With the default, the same user is a viewer of `default`.
    let open = harness_with("open", true, Some("default"), SessionPolicy::default());
    let (cookie, _) = open.login("stranger");
    let body = granted(open.mint(&cookie, audience()).await).await;
    assert_eq!(body["tenant"], "default");
    assert_eq!(body["roles"], serde_json::json!(["viewer"]));
    assert_eq!(body["indexes"], serde_json::json!(["*"]));
    let (_, claims) = open.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims["tenant"], "default");

    // Asking for the default by name works; asking for another tenant does not.
    granted(
        open.mint(
            &cookie,
            serde_json::json!({ "audience": "logless", "tenant": "default" }),
        )
        .await,
    )
    .await;
    assert_eq!(
        refused(
            open.mint(
                &cookie,
                serde_json::json!({ "audience": "logless", "tenant": "acme" }),
            )
            .await
        )
        .await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );

    // A user the operator revoked is not rescued by the default: the table has
    // spoken about them.
    open.grant("banned", "acme", &["viewer"], &["*"]).await;
    open.admin("DELETE", "/admin/user-grants/banned/acme", None)
        .await;
    let (banned, _) = open.login("banned");
    assert_eq!(
        refused(open.mint(&banned, audience()).await).await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );

    // Nor is a user whose only grant sits in a disabled tenant.
    open.grant("orphan", "globex", &["viewer"], &["*"]).await;
    open.admin("DELETE", "/admin/tenants/globex", None).await;
    let (orphan, _) = open.login("orphan");
    assert_eq!(
        refused(open.mint(&orphan, audience()).await).await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );
}

/// The default-tenant fallback is a grant the install makes on the user's
/// behalf; a tenant the operator disabled grants nothing, same as the
/// explicit-grant path.
#[tokio::test]
async fn the_default_tenant_fallback_stops_when_that_tenant_is_disabled() {
    let h = harness_with(
        "default-off",
        true,
        Some("default"),
        SessionPolicy::default(),
    );
    let (cookie, _) = h.login("stranger");

    // Matches: the default tenant is live.
    assert_eq!(
        granted(h.mint(&cookie, audience()).await).await["tenant"],
        "default"
    );

    // Does not match: the default tenant disabled.
    assert_eq!(
        h.admin("DELETE", "/admin/tenants/default", None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        refused(h.mint(&cookie, audience()).await).await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );
    assert_eq!(
        refused(
            h.mint(
                &cookie,
                serde_json::json!({ "audience": "logless", "tenant": "default" })
            )
            .await
        )
        .await,
        (StatusCode::FORBIDDEN, "not_granted".to_owned())
    );

    // Matches again once the operator enables it.
    assert_eq!(
        h.admin("POST", "/admin/tenants/default/enable", None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        granted(h.mint(&cookie, audience()).await).await["tenant"],
        "default"
    );
}

// --- off, audit, metrics, INV-12 --------------------------------------------

#[tokio::test]
async fn the_route_answers_501_until_the_issuer_is_configured() {
    let h = harness_with("off", false, None, SessionPolicy::default());
    let (cookie, _) = h.login("user-1");
    assert_eq!(
        refused(h.mint(&cookie, audience()).await).await,
        (StatusCode::NOT_IMPLEMENTED, "lane_disabled".to_owned())
    );
    // The feature being off creates nothing: no signing key, no audit row.
    assert!(repo::list_signing_keys(&h.connect()).unwrap().is_empty());
    assert!(h.audit(action::TOKEN_ISSUANCE_REFUSED).is_empty());
}

#[tokio::test]
async fn issuance_is_audited_with_the_subject_and_no_token_and_refusals_always() {
    let h = harness("audit");
    h.grant("user-1", "acme", &["admin"], &["main"]).await;
    let (cookie, sid) = h.login("user-1");

    let mut tokens = Vec::new();
    for _ in 0..3 {
        let body = granted(h.mint(&cookie, audience()).await).await;
        tokens.push(body["access_token"].as_str().unwrap().to_owned());
    }
    let issued = h.audit(action::TOKEN_ISSUED);
    assert_eq!(issued.len(), 1, "three tokens, one row");
    let row = &issued[0].row;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.actor_kind, "user");
    assert_eq!(row.subject.as_deref(), Some("user-1"));
    assert_eq!(row.sid.as_deref(), Some(sid.as_str()));
    let detail: serde_json::Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["aud"], "logless");
    assert_eq!(detail["kind"], "user");
    assert_eq!(detail["tenant"], "acme");
    assert_eq!(detail["ttl"], 3_600);
    assert_eq!(detail["kid"].as_str().unwrap().len(), 11);
    assert_eq!(detail["jti"].as_str().unwrap().len(), 22);

    // The window is per (subject, audience): one second short of it, then past.
    h.clock.advance(299);
    granted(h.mint(&cookie, audience()).await).await;
    assert_eq!(h.audit(action::TOKEN_ISSUED).len(), 1);
    h.clock.advance(1);
    granted(h.mint(&cookie, audience()).await).await;
    assert_eq!(h.audit(action::TOKEN_ISSUED).len(), 2);

    // Refusals are rows, each one, and carry the code.
    for _ in 0..2 {
        let _ = h
            .mint(&cookie, serde_json::json!({ "audience": "nope" }))
            .await;
    }
    let _ = h
        .mint(
            &cookie,
            serde_json::json!({ "audience": "logless", "tenant": "initech" }),
        )
        .await;
    let refusals = h.audit(action::TOKEN_ISSUANCE_REFUSED);
    assert_eq!(refusals.len(), 3);
    let mut reasons: Vec<_> = refusals
        .iter()
        .map(|r| r.row.reason.clone().unwrap())
        .collect();
    reasons.sort();
    assert_eq!(reasons, ["bad_audience", "bad_audience", "not_granted"]);
    assert!(refusals
        .iter()
        .all(|r| r.row.subject.as_deref() == Some("user-1") && r.row.outcome == "failure"));

    // The counters, by outcome, for the user kind.
    let metrics = h.metrics.render(&Default::default());
    assert!(metrics.contains(r#"broker_tokens_issued_total{kind="user",outcome="issued"} 5"#));
    assert!(metrics.contains(r#"broker_tokens_issued_total{kind="user",outcome="bad_audience"} 2"#));
    assert!(metrics.contains(r#"broker_tokens_issued_total{kind="user",outcome="not_granted"} 1"#));

    // Nothing in the record is a token or the cookie.
    let rows = format!(
        "{:?}",
        repo::list_audit(
            &h.connect(),
            &AuditQuery {
                limit: 1000,
                ..AuditQuery::default()
            },
        )
        .unwrap()
    );
    for token in &tokens {
        for part in token.split('.') {
            assert!(!rows.contains(part), "a token segment is in an audit row");
        }
    }
    assert!(!rows.contains(&cookie));
}

#[tokio::test]
async fn no_token_or_cookie_reaches_the_log_or_a_metric() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }
    // See the same guard in `http::token::tests`: a second live subscriber
    // keeps `tracing` asking every subscriber, so the capture below is not
    // silently empty when other tests share the process.
    let _keeps_interest_honest = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = harness("inv12");
    h.grant("user-1", "acme", &["admin"], &["main"]).await;
    let (cookie, _) = h.login("user-1");
    let body = granted(h.mint(&cookie, audience()).await).await;
    let token = body["access_token"].as_str().unwrap().to_owned();
    let _ = h
        .mint(&cookie, serde_json::json!({ "audience": "nope" }))
        .await;
    h.flush();

    let log = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(log.contains("token.issued"), "the capture works: {log}");
    assert!(log.contains("token.issuance_refused"));
    let metrics = h.metrics.render(&Default::default());
    let segments: Vec<&str> = token.split('.').collect();
    for (label, needle) in [
        ("the session cookie", cookie.as_str()),
        ("the token", token.as_str()),
        ("the token's claims", segments[1]),
        ("the token's signature", segments[2]),
    ] {
        assert!(!log.contains(needle), "{label} is in the log");
        assert!(!metrics.contains(needle), "{label} is in a metric");
    }
}
