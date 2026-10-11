//! Tests for `POST /auth/token`.
//!
//! Principals are made and revoked through the admin routes, on the same store
//! the token route reads, so each test crosses the two lanes the way a
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
use crate::ratelimit::{Limiter, Quota};
use crate::session::{SessionMap, SessionPolicy};
use crate::store::repo::{self, AuditQuery, StoredAuditRow};
use crate::store::writer::{AdminWrite, Writer};
use crate::store::Reader;
use crate::telemetry::Metrics;

const T0: Timestamp = Timestamp(1_700_000_000);
const ISSUER: &str = "https://broker.example.com";
const ADMIN_KEY: &str = "an-admin-key-that-is-at-least-32-chars";
const FORM: &str = "application/x-www-form-urlencoded";

struct Harness {
    /// The public router, hardened as `main` hardens it.
    app: Router,
    admin: Router,
    clock: TestClock,
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

fn issuer_config() -> IssuerConfig {
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
        default_user_tenant: Some("default".to_owned()),
        default_user_roles: vec!["viewer".to_owned()],
    }
}

/// `failure_burst` wrong credentials per client id per minute; `None` is no
/// limiter. The public lane's own limiter is always off (`rate_limit: None`),
/// which is what a deployment with no client-IP header configured has.
fn harness_with(tag: &str, configured: bool, failure_burst: Option<u32>) -> Harness {
    let path = std::env::temp_dir().join(format!(
        "session-broker-token-{tag}-{}-{}.sqlite3",
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
    let policy = SessionPolicy::default();
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
            config: Arc::new(issuer_config()),
            client_failures: failure_burst
                .map(|burst| Arc::new(Limiter::new(Quota::new(burst, 60), 128))),
        }),
    };
    let admin = crate::http::admin::router(AdminState {
        sessions,
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
        metrics,
        path,
        writer,
    }
}

fn harness(tag: &str) -> Harness {
    harness_with(tag, true, None)
}

struct Principal {
    id: String,
    secret: String,
    secret_id: String,
}

impl Harness {
    async fn admin(
        &self,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {ADMIN_KEY}"));
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
        let response = self
            .admin
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        (response.status(), json(response).await)
    }

    /// An `ingest` principal in tenant `acme`, with `extra` laid over the
    /// defaults.
    async fn principal(&self, name: &str, extra: serde_json::Value) -> Principal {
        let mut body = serde_json::json!({
            "name": name,
            "tenant": "acme",
            "kind": "ingest",
            "scopes": ["ingest", "read"],
            "indexes": ["main", "audit"],
            "audience": "logless",
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let (status, body) = self.admin("POST", "/admin/principals", Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        Principal {
            id: body["principal_id"].as_str().unwrap().to_owned(),
            secret: body["secret"]["secret"].as_str().unwrap().to_owned(),
            secret_id: body["secret"]["secret_id"].as_str().unwrap().to_owned(),
        }
    }

    async fn post(&self, content_type: &str, basic: Option<&str>, body: String) -> Response {
        let mut request = Request::builder()
            .method("POST")
            .uri("/auth/token")
            .header(header::CONTENT_TYPE, content_type);
        if let Some(basic) = basic {
            request = request.header(header::AUTHORIZATION, basic);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    /// The ordinary request, with `extra` (`&name=value...`) appended.
    async fn token(&self, id: &str, secret: &str, extra: &str) -> Response {
        self.post(
            FORM,
            None,
            format!("grant_type=client_credentials&client_id={id}&client_secret={secret}{extra}"),
        )
        .await
    }

    /// Wait for the writer to commit everything enqueued so far. Commands are
    /// applied in order, and this one is acknowledged only after its batch
    /// commits.
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

    fn last_used_at(&self, id: &str) -> Option<Timestamp> {
        self.flush();
        repo::get_principal(&self.connect(), id)
            .unwrap()
            .unwrap()
            .last_used_at
    }

    /// Verify with an independent decoder against the keys the broker serves.
    /// `exp` is checked by the caller: the broker runs on a test clock, the
    /// decoder on the wall clock.
    async fn verify(&self, token: &str) -> (jsonwebtoken::Header, serde_json::Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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
    let body = json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// A refusal's status, its `WWW-Authenticate`, and its body as sent.
async fn refused(response: Response) -> (StatusCode, Option<String>, String) {
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_owned());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        challenge,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn error_code(response: Response) -> (StatusCode, String) {
    let (status, _, body) = refused(response).await;
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(body["error_description"].is_string(), "{body}");
    (status, body["error"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn a_principal_gets_a_token_whose_every_claim_comes_from_its_row() {
    let h = harness("happy");
    let p = h.principal("edge-1", serde_json::json!({})).await;

    let response = h.token(&p.id, &p.secret, "").await;
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    let body = granted(response).await;
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 86_400);
    assert_eq!(body["scope"], "ingest read");
    assert_eq!(body.as_object().unwrap().len(), 4, "RFC 6749 §5.1: {body}");

    let (header, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.typ.as_deref(), Some("JWT"));

    let jti = claims["jti"].as_str().unwrap().to_owned();
    assert_eq!(jti.len(), 22, "16 random bytes, base64url");
    assert_eq!(
        claims,
        serde_json::json!({
            "iss": ISSUER,
            "sub": p.id,
            "aud": "logless",
            "exp": T0.secs() + 86_400,
            "iat": T0.secs(),
            "jti": jti,
            "tenant": "acme",
            "kind": "ingest",
            "name": "edge-1",
            "scopes": ["ingest", "read"],
            "indexes": ["main", "audit"],
        }),
        "these claims and no others"
    );
    assert!(claims["aud"].is_string(), "one audience, not a list");

    // A second token is a different token.
    let again = granted(h.token(&p.id, &p.secret, "").await).await;
    let (_, second) = h.verify(again["access_token"].as_str().unwrap()).await;
    assert_ne!(second["jti"], claims["jti"]);
}

#[tokio::test]
async fn the_lifetime_is_capped_by_the_principals_maximum() {
    let h = harness("ttl");
    let short = h
        .principal("short", serde_json::json!({"max_ttl_secs": 600}))
        .await;
    let long = h.principal("long", serde_json::json!({})).await;

    // No ttl asked for: the default, or the principal's maximum if that is less.
    let body = granted(h.token(&short.id, &short.secret, "").await).await;
    assert_eq!(body["expires_in"], 600);
    let (_, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        600
    );

    // A ttl inside the maximum is honoured, shorter or longer than the default.
    for (p, ttl) in [(&short, 600), (&short, 60), (&long, 2_592_000)] {
        let body = granted(h.token(&p.id, &p.secret, &format!("&ttl={ttl}")).await).await;
        assert_eq!(body["expires_in"], ttl);
        let (_, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            ttl
        );
    }

    // One past it is refused, not quietly shortened.
    for (p, ttl) in [
        (&short, "601"),
        (&long, "2592001"),
        (&long, "0"),
        (&long, "soon"),
    ] {
        let response = h.token(&p.id, &p.secret, &format!("&ttl={ttl}")).await;
        assert_eq!(
            error_code(response).await,
            (StatusCode::BAD_REQUEST, "invalid_request".to_owned()),
            "ttl={ttl}"
        );
    }
}

#[tokio::test]
async fn every_dead_credential_gets_the_same_401() {
    let h = harness("dead");
    let live = h.principal("live", serde_json::json!({})).await;

    // The reference refusal: a wrong secret for a real principal.
    let wrong = format!("sbp_{}", "A".repeat(43));
    let reference = refused(h.token(&live.id, &wrong, "").await).await;
    assert_eq!(reference.0, StatusCode::UNAUTHORIZED);
    assert!(reference.1.as_deref().unwrap().starts_with("Basic "));
    let body: serde_json::Value = serde_json::from_str(&reference.2).unwrap();
    assert_eq!(body["error"], "invalid_client");

    // A revoked principal.
    let revoked = h.principal("revoked", serde_json::json!({})).await;
    granted(h.token(&revoked.id, &revoked.secret, "").await).await;
    let (status, _) = h
        .admin("DELETE", &format!("/admin/principals/{}", revoked.id), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        refused(h.token(&revoked.id, &revoked.secret, "").await).await,
        reference
    );

    // A revoked secret, while the principal's second secret still works.
    let rotated = h.principal("rotated", serde_json::json!({})).await;
    let (status, added) = h
        .admin(
            "POST",
            &format!("/admin/principals/{}/secrets", rotated.id),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = h
        .admin(
            "DELETE",
            &format!(
                "/admin/principals/{}/secrets/{}",
                rotated.id, rotated.secret_id
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        refused(h.token(&rotated.id, &rotated.secret, "").await).await,
        reference
    );
    granted(
        h.token(&rotated.id, added["secret"].as_str().unwrap(), "")
            .await,
    )
    .await;

    // An expired secret: good one second before, dead at the moment it expires.
    let expiring = h
        .principal("expiring", serde_json::json!({"expires_in_secs": 100}))
        .await;
    h.clock.advance(99);
    granted(h.token(&expiring.id, &expiring.secret, "").await).await;
    h.clock.advance(1);
    assert_eq!(
        refused(h.token(&expiring.id, &expiring.secret, "").await).await,
        reference
    );

    // A principal nobody created, a secret of the wrong class, a real secret
    // under another principal's id, and no credentials at all.
    assert_eq!(
        refused(h.token("sp_nobodymadethis00", &wrong, "").await).await,
        reference
    );
    assert_eq!(
        refused(h.token(&live.id, ADMIN_KEY, "").await).await,
        reference
    );
    let other = h.principal("other", serde_json::json!({})).await;
    assert_eq!(
        refused(h.token(&other.id, &live.secret, "").await).await,
        reference
    );
    assert_eq!(
        refused(
            h.post(FORM, None, "grant_type=client_credentials".to_owned())
                .await
        )
        .await,
        reference
    );

    // A disabled tenant, last: it takes every principal in `acme` with it.
    granted(h.token(&live.id, &live.secret, "").await).await;
    let (status, _) = h.admin("DELETE", "/admin/tenants/acme", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        refused(h.token(&live.id, &live.secret, "").await).await,
        reference
    );
}

#[tokio::test]
async fn a_requested_scope_must_be_a_subset_of_the_principals() {
    let h = harness("scope");
    let p = h.principal("edge", serde_json::json!({})).await;

    // Narrowing works, and the token carries only what was asked for.
    let body = granted(h.token(&p.id, &p.secret, "&scope=read").await).await;
    assert_eq!(body["scope"], "read");
    let (_, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims["scopes"], serde_json::json!(["read"]));

    // Everything it holds, in the caller's order, said twice.
    let body = granted(h.token(&p.id, &p.secret, "&scope=read+ingest+read").await).await;
    assert_eq!(body["scope"], "read ingest");

    // One scope it does not hold spoils the request.
    for scope in ["admin", "ingest+admin", "*"] {
        let response = h.token(&p.id, &p.secret, &format!("&scope={scope}")).await;
        assert_eq!(
            error_code(response).await,
            (StatusCode::BAD_REQUEST, "invalid_scope".to_owned()),
            "scope={scope}"
        );
    }
}

#[tokio::test]
async fn only_a_form_body_is_accepted() {
    let h = harness("form");
    let p = h.principal("edge", serde_json::json!({})).await;

    let as_json = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": p.id,
        "client_secret": p.secret,
    })
    .to_string();
    let response = h.post("application/json", None, as_json.clone()).await;
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".to_owned())
    );
    // JSON under the form content type is not a form either.
    let response = h.post(FORM, None, as_json).await;
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".to_owned())
    );

    // Other ways a request is malformed.
    let creds = format!("client_id={}&client_secret={}", p.id, p.secret);
    for (body, code) in [
        (creds.clone(), "invalid_request"),
        (
            format!("grant_type=password&{creds}"),
            "unsupported_grant_type",
        ),
        (
            format!("grant_type=client_credentials&{creds}&client_id={}", p.id),
            "invalid_request",
        ),
    ] {
        let response = h.post(FORM, None, body.clone()).await;
        assert_eq!(
            error_code(response).await,
            (StatusCode::BAD_REQUEST, code.to_owned()),
            "{body}"
        );
    }
}

#[tokio::test]
async fn a_tenant_or_audience_in_the_request_is_ignored() {
    let h = harness("tenant");
    let p = h.principal("edge", serde_json::json!({})).await;

    let body = granted(
        h.token(
            &p.id,
            &p.secret,
            "&tenant=evil&tenant_id=evil&audience=other&aud=other&kind=admin&indexes=*&name=root",
        )
        .await,
    )
    .await;
    let (_, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims["tenant"], "acme");
    assert_eq!(claims["aud"], "logless");
    assert_eq!(claims["kind"], "ingest");
    assert_eq!(claims["name"], "edge");
    assert_eq!(claims["indexes"], serde_json::json!(["main", "audit"]));
}

#[tokio::test]
async fn http_basic_carries_the_credentials_too() {
    use base64::Engine as _;
    let h = harness("basic");
    let p = h.principal("edge", serde_json::json!({})).await;
    let basic = |id: &str, secret: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
        )
    };
    let grant = "grant_type=client_credentials".to_owned();

    let body = granted(
        h.post(FORM, Some(&basic(&p.id, &p.secret)), grant.clone())
            .await,
    )
    .await;
    let (_, claims) = h.verify(body["access_token"].as_str().unwrap()).await;
    assert_eq!(claims["sub"], p.id.as_str());

    // A wrong secret, and a header that is not Basic at all.
    let wrong = format!("sbp_{}", "B".repeat(43));
    for header in [basic(&p.id, &wrong), format!("Bearer {}", p.secret)] {
        let response = h.post(FORM, Some(&header), grant.clone()).await;
        assert_eq!(
            error_code(response).await,
            (StatusCode::UNAUTHORIZED, "invalid_client".to_owned())
        );
    }

    // Both methods at once is a malformed request, even when both are right.
    let response = h
        .post(
            FORM,
            Some(&basic(&p.id, &p.secret)),
            format!("{grant}&client_id={}&client_secret={}", p.id, p.secret),
        )
        .await;
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".to_owned())
    );
}

#[tokio::test]
async fn a_principal_bound_to_an_unconfigured_audience_gets_no_token() {
    let h = harness("aud");
    let p = h
        .principal("stray", serde_json::json!({"audience": "elsewhere"}))
        .await;
    let response = h.token(&p.id, &p.secret, "").await;
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "unauthorized_client".to_owned())
    );
}

/// The wiring test for `AdminWrite::TouchPrincipal`: through the handler, and
/// read back on another connection.
#[tokio::test]
async fn issuing_a_token_records_when_the_principal_was_last_used() {
    let h = harness("touch");
    let p = h.principal("edge", serde_json::json!({})).await;
    let idle = h.principal("idle", serde_json::json!({})).await;
    assert_eq!(h.last_used_at(&p.id), None);

    // A refusal is not a use.
    let wrong = format!("sbp_{}", "C".repeat(43));
    let _ = h.token(&p.id, &wrong, "").await;
    assert_eq!(h.last_used_at(&p.id), None);

    h.clock.advance(5);
    granted(h.token(&p.id, &p.secret, "").await).await;
    assert_eq!(h.last_used_at(&p.id), Some(T0.plus_secs(5)));
    assert_eq!(h.last_used_at(&idle.id), None, "only the one that was used");

    // Coalesced: inside a minute nothing is written, after it the time moves.
    h.clock.advance(59);
    granted(h.token(&p.id, &p.secret, "").await).await;
    assert_eq!(h.last_used_at(&p.id), Some(T0.plus_secs(5)));
    h.clock.advance(1);
    granted(h.token(&p.id, &p.secret, "").await).await;
    assert_eq!(h.last_used_at(&p.id), Some(T0.plus_secs(65)));
}

#[tokio::test]
async fn wrong_secrets_run_out_per_client_id_with_no_client_ip_configured() {
    let h = harness_with("limit", true, Some(3));
    let p = h.principal("edge", serde_json::json!({})).await;
    let other = h.principal("other", serde_json::json!({})).await;
    let wrong = format!("sbp_{}", "D".repeat(43));

    for guess in 0..3 {
        let response = h.token(&p.id, &wrong, "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "guess {guess}");
    }
    let response = h.token(&p.id, &wrong, "").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("a 429 says when to come back")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry_after), "{retry_after}");
    assert_eq!(json(response).await["error"], "rate_limited");

    // The budget belongs to the id that was guessed against: another client's
    // wrong secret is still judged on its merits.
    let response = h.token(&other.id, &wrong, "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // And it only ever counts failures: the real holder of the secret is not
    // locked out by the guessing, and issuing tokens spends nothing.
    for _ in 0..5 {
        granted(h.token(&p.id, &p.secret, "").await).await;
    }

    // Ids that are not shaped like one share a single bucket.
    for guess in 0..3 {
        let response = h.token(&format!("nonsense-{guess}"), &wrong, "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = h.token("something-else-again", &wrong, "").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let rendered = h.metrics.render(&Default::default());
    assert!(
        rendered.contains(r#"broker_rate_limited_total{lane="public",bucket="issuer_client"} 2"#),
        "{rendered}"
    );
    // Past the budget a guess is counted, not recorded.
    assert_eq!(h.audit(action::TOKEN_ISSUANCE_REFUSED).len(), 3 + 1 + 3);
}

/// An id the store has never issued is attacker-chosen text: a budget per id
/// would be a fresh budget per request, and a fresh audit row with it.
#[tokio::test]
async fn ids_that_name_no_principal_share_one_budget_and_one_trickle_of_audit_rows() {
    let h = harness_with("limit-unknown", true, Some(3));
    let p = h.principal("edge", serde_json::json!({})).await;
    let wrong = format!("sbp_{}", "F".repeat(43));

    // Matches the shared bucket: ids that look right and exist nowhere.
    for n in 0..3 {
        let response = h.token(&format!("sp_guess{n}"), &wrong, "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "guess {n}");
    }
    for n in 3..20 {
        let response = h.token(&format!("sp_guess{n}"), &wrong, "").await;
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "guess {n}"
        );
    }
    // One row per spent unit of the shared budget, none for the rest.
    assert_eq!(h.audit(action::TOKEN_ISSUANCE_REFUSED).len(), 3);

    // Does not match: a real principal keeps a budget of its own, and its
    // right secret was never in the shared bucket's way.
    for guess in 0..3 {
        let response = h.token(&p.id, &wrong, "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "guess {guess}");
    }
    assert_eq!(
        h.token(&p.id, &wrong, "").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    granted(h.token(&p.id, &p.secret, "").await).await;
    assert_eq!(h.audit(action::TOKEN_ISSUANCE_REFUSED).len(), 6);
}

#[tokio::test]
async fn issuance_is_recorded_once_per_window_and_every_refusal_is_recorded() {
    let h = harness("audit");
    let p = h.principal("edge", serde_json::json!({})).await;
    let other = h.principal("other", serde_json::json!({})).await;

    for _ in 0..3 {
        granted(h.token(&p.id, &p.secret, "").await).await;
    }
    let issued = h.audit(action::TOKEN_ISSUED);
    assert_eq!(issued.len(), 1, "three tokens, one row");
    let row = &issued[0].row;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.actor_kind, "backend");
    assert_eq!(row.actor_id.as_deref(), Some(p.id.as_str()));
    assert_eq!(row.key_id.as_deref(), Some(p.id.as_str()));
    let detail: serde_json::Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["aud"], "logless");
    assert_eq!(detail["kind"], "ingest");
    assert_eq!(detail["tenant"], "acme");
    assert_eq!(detail["ttl"], 86_400);
    assert_eq!(detail["kid"].as_str().unwrap().len(), 11);
    assert_eq!(detail["jti"].as_str().unwrap().len(), 22);

    // Another principal is another row; the window is per (principal, audience).
    granted(h.token(&other.id, &other.secret, "").await).await;
    assert_eq!(h.audit(action::TOKEN_ISSUED).len(), 2);

    // Still inside the window one second before it ends, a new row after it.
    h.clock.advance(299);
    granted(h.token(&p.id, &p.secret, "").await).await;
    assert_eq!(h.audit(action::TOKEN_ISSUED).len(), 2);
    h.clock.advance(1);
    granted(h.token(&p.id, &p.secret, "").await).await;
    assert_eq!(h.audit(action::TOKEN_ISSUED).len(), 3);

    // Refusals: one row each, however alike they are.
    let wrong = format!("sbp_{}", "E".repeat(43));
    for _ in 0..3 {
        let _ = h.token(&p.id, &wrong, "").await;
    }
    let _ = h.token(&p.id, &p.secret, "&scope=admin").await;
    let refusals = h.audit(action::TOKEN_ISSUANCE_REFUSED);
    assert_eq!(refusals.len(), 4);
    assert_eq!(refusals[0].row.reason.as_deref(), Some("invalid_scope"));
    for refusal in &refusals[1..] {
        assert_eq!(refusal.row.reason.as_deref(), Some("invalid_client"));
        assert_eq!(refusal.row.outcome, "failure");
        assert_eq!(refusal.row.actor_id.as_deref(), Some(p.id.as_str()));
    }

    // A request that names no credential is counted, not recorded.
    let _ = h.post("application/json", None, "{}".to_owned()).await;
    assert_eq!(h.audit(action::TOKEN_ISSUANCE_REFUSED).len(), 4);

    let rendered = h.metrics.render(&Default::default());
    for series in [
        r#"broker_tokens_issued_total{kind="ingest",outcome="issued"} 6"#,
        r#"broker_tokens_issued_total{kind="machine",outcome="invalid_client"} 3"#,
        r#"broker_tokens_issued_total{kind="ingest",outcome="invalid_scope"} 1"#,
        r#"broker_tokens_issued_total{kind="machine",outcome="invalid_request"} 1"#,
    ] {
        assert!(
            rendered.contains(series),
            "{series} missing from:\n{rendered}"
        );
    }
}

/// INV-12, by looking: drive the route through success and every refusal with
/// the log captured at TRACE, then search the log, the audit rows and the
/// database file for the secret and for the token.
#[tokio::test]
async fn no_secret_or_token_reaches_the_log_the_audit_record_or_the_metrics() {
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
    // `tracing` caches, per call site, whether anyone is listening. While only
    // one subscriber exists in the process it asks the *calling thread's*
    // subscriber, so a call site first reached by another test's thread is
    // cached as "nobody" and stays silent here. A second live subscriber makes
    // it ask every subscriber instead. Without this the test passes alone and
    // fails in the full suite; the assertions that the capture is not empty
    // are what show it.
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
    // The test runtime is single-threaded, so every handler below runs under
    // this subscriber.
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = harness_with("inv12", true, Some(2));
    let p = h.principal("edge", serde_json::json!({})).await;
    let wrong = format!("sbp_{}", "F".repeat(43));

    let body = granted(h.token(&p.id, &p.secret, "").await).await;
    let token = body["access_token"].as_str().unwrap().to_owned();
    let _ = h.token(&p.id, &p.secret, "&scope=admin").await;
    let _ = h.token(&p.id, &p.secret, "&ttl=99999999999").await;
    // The secret where the id belongs, which is what a muddled client sends.
    let _ = h.token(&p.secret, &p.secret, "").await;
    for _ in 0..4 {
        let _ = h.token(&p.id, &wrong, "").await;
    }
    h.flush();

    let log = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(log.contains("token.issued"), "the capture works: {log}");
    assert!(log.contains("token.issuance_refused"));
    assert!(log.contains("rate limit tripped"));

    let rows = repo::list_audit(
        &h.connect(),
        &AuditQuery {
            limit: 1000,
            ..AuditQuery::default()
        },
    )
    .unwrap();
    let audit = format!("{rows:?}");
    assert!(audit.contains("token.issued") && audit.contains("token.issuance_refused"));
    let metrics = h.metrics.render(&Default::default());

    // The signature alone would identify the token, so each segment is looked
    // for by itself, as well as the secrets with their prefix cut off.
    let segments: Vec<&str> = token.split('.').collect();
    let needles = [
        ("the principal secret", p.secret.as_str()),
        ("the principal secret, unprefixed", &p.secret[4..]),
        ("a wrong secret", wrong.as_str()),
        ("the token", token.as_str()),
        ("the token's claims", segments[1]),
        ("the token's signature", segments[2]),
    ];
    for (label, needle) in needles {
        assert!(!log.contains(needle), "{label} is in the log");
        assert!(!audit.contains(needle), "{label} is in an audit row");
        assert!(!metrics.contains(needle), "{label} is in a metric");
    }
    // The identifiers that are allowed are there, so the search above was not
    // passing on an empty record.
    assert!(log.contains(&p.id) && audit.contains(&p.id));
}

#[tokio::test]
async fn the_route_answers_501_until_the_issuer_is_configured() {
    let h = harness_with("off", false, Some(3));
    // Whatever is sent: a well-formed request, a JSON body, nothing at all.
    for (content_type, body) in [
        (
            FORM,
            "grant_type=client_credentials&client_id=sp_x&client_secret=sbp_x",
        ),
        ("application/json", "{}"),
        (FORM, ""),
    ] {
        let response = h.post(content_type, None, body.to_owned()).await;
        assert_eq!(
            error_code(response).await,
            (StatusCode::NOT_IMPLEMENTED, "lane_disabled".to_owned())
        );
    }
    assert!(h.audit(action::TOKEN_ISSUANCE_REFUSED).is_empty());
    // The feature being off creates nothing: no signing key either.
    assert!(repo::list_signing_keys(&h.connect()).unwrap().is_empty());
}

#[tokio::test]
async fn the_metadata_advertises_the_token_endpoint() {
    let h = harness("meta");
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json(response).await;
    assert_eq!(body["token_endpoint"], format!("{ISSUER}/auth/token"));
    assert_eq!(
        body["grant_types_supported"],
        serde_json::json!(["client_credentials"])
    );
    assert_eq!(
        body["token_endpoint_auth_methods_supported"],
        serde_json::json!(["client_secret_post", "client_secret_basic"])
    );
}
