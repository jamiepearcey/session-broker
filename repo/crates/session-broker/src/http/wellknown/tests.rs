//! Tests for the published documents. The router is wrapped in the same
//! hardening layer `main` applies, because the failure worth catching is that
//! layer turning a cacheable document into `no-store`. The keys come from a
//! real store through `bootstrap` and `rotate`, and a token is checked against
//! what the route serves rather than against the signer's own state.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt as _;

use super::*;
use crate::audit::{AuditConfig, AuditSink};
use crate::clock::{Clock, TestClock, Timestamp};
use crate::config::IssuerConfig;
use crate::http::{hardening, HttpConfig};
use crate::issuer::{bootstrap, KeyPolicy};
use crate::session::{SessionMap, SessionPolicy};
use crate::store::writer::Writer;
use crate::store::Reader;
use crate::telemetry::Metrics;

/// 2023-11-14T22:13:20Z.
const T0: Timestamp = Timestamp(1_700_000_000);
const ISSUER: &str = "https://broker.example.com";

struct Harness {
    app: Router,
    issuer: Option<Arc<crate::issuer::Issuer>>,
    path: std::path::PathBuf,
    _writer: Option<Writer>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
        let _ = std::fs::remove_file(self.path.with_extension("key"));
    }
}

fn issuer_config(max_age: u64) -> IssuerConfig {
    IssuerConfig {
        issuer: ISSUER.to_owned(),
        audiences: vec!["logless".to_owned()],
        machine_ttl_secs: 86_400,
        user_ttl_secs: 3_600,
        max_ttl_secs: 86_400,
        publish_lead_secs: 86_400,
        jwks_max_age_secs: max_age,
        jwks_uri: format!("{ISSUER}/auth/jwks.json"),
        token_endpoint: format!("{ISSUER}/auth/token"),
        default_user_tenant: Some("default".to_owned()),
        default_user_roles: vec!["viewer".to_owned()],
    }
}

/// The public router, hardened. `configured: false` leaves the issuer off.
fn harness(tag: &str, configured: bool, max_age: u64) -> Harness {
    let path = std::env::temp_dir().join(format!(
        "session-broker-wellknown-{tag}-{}-{}.sqlite3",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let keyfile = path.with_extension("key");
    let writer = Writer::spawn(crate::store::open(&path, &keyfile).unwrap());
    let clock = TestClock::new(T0);
    let metrics = Metrics::new();

    let issuer = configured.then(|| {
        bootstrap(
            Arc::new(Reader::new(crate::store::open(&path, &keyfile).unwrap())),
            writer.handle(),
            Some(AuditSink::new(
                writer.handle(),
                metrics.clone(),
                AuditConfig::default(),
            )),
            Arc::new(clock.clone()),
            KeyPolicy::default(),
        )
        .unwrap()
    });
    let policy = SessionPolicy::default();
    let state = AppState {
        sessions: Arc::new(SessionMap::new(policy)),
        clock: Arc::new(clock),
        config: Arc::new(HttpConfig::new(ISSUER, &policy).unwrap()),
        custody: None,
        audit: None,
        metrics,
        rate_limit: None,
        issuer: issuer.clone().map(|signer| IssuerHandle {
            signer,
            config: Arc::new(issuer_config(max_age)),
            client_failures: None,
        }),
    };
    Harness {
        app: hardening::apply(super::super::router(state), hardening::Hardening::default()),
        issuer,
        path,
        _writer: Some(writer),
    }
}

impl Harness {
    async fn get(&self, path: &str, if_none_match: Option<&str>) -> Response {
        let mut request = Request::builder().method("GET").uri(path);
        if let Some(tag) = if_none_match {
            request = request.header(header::IF_NONE_MATCH, tag);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
}

async fn json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn header_of(response: &Response, name: header::HeaderName) -> String {
    response
        .headers()
        .get(name)
        .expect("header present")
        .to_str()
        .unwrap()
        .to_owned()
}

const PATHS: [&str; 2] = ["/auth/jwks.json", "/.well-known/oauth-authorization-server"];

#[tokio::test]
async fn both_documents_answer_501_while_the_issuer_is_unconfigured() {
    let h = harness("off", false, 300);
    for path in PATHS {
        let response = h.get(path, None).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{path}");
        assert_eq!(header_of(&response, header::CACHE_CONTROL), "no-store");
        let body = json(response).await;
        assert_eq!(body["error"], "lane_disabled", "{path}");
    }
}

#[tokio::test]
async fn the_documents_are_cacheable_and_survive_the_hardening_layer() {
    let h = harness("cache", true, 123);
    for path in PATHS {
        let response = h.get(path, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let cache = header_of(&response, header::CACHE_CONTROL);
        assert!(!cache.contains("no-store"), "{path}: {cache}");
        assert_eq!(
            cache, "public, max-age=123, stale-if-error=2592000",
            "{path}: max-age comes from config"
        );
        assert_eq!(
            header_of(&response, header::DATE),
            "Tue, 14 Nov 2023 22:13:20 GMT",
            "{path}: Date is the broker's clock"
        );
        assert_eq!(
            header_of(&response, header::CONTENT_TYPE),
            "application/json"
        );
        // The rest of the hardening headers still apply.
        assert_eq!(
            header_of(&response, header::X_CONTENT_TYPE_OPTIONS),
            "nosniff"
        );
    }
}

#[tokio::test]
async fn the_metadata_names_the_configured_issuer_and_key_location() {
    let h = harness("meta", true, 300);
    let body = json(h.get("/.well-known/oauth-authorization-server", None).await).await;
    let config = issuer_config(300);
    assert_eq!(body["issuer"], config.issuer);
    assert_eq!(body["jwks_uri"], config.jwks_uri);
    assert_eq!(
        body["jwks_uri"],
        "https://broker.example.com/auth/jwks.json"
    );

    // The advertised location is a route that exists and serves keys.
    let keys = json(h.get("/auth/jwks.json", None).await).await;
    assert_eq!(keys["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_token_signed_here_verifies_against_the_keys_the_route_serves() {
    let h = harness("verify", true, 300);
    let issuer = h.issuer.clone().unwrap();
    let now = crate::clock::SystemClock.now().secs();
    let token = issuer
        .sign(&serde_json::json!({
            "iss": ISSUER,
            "sub": "sp_test",
            "aud": "logless",
            "iat": now,
            "exp": now + 3600,
        }))
        .unwrap();

    let fetched = json(h.get("/auth/jwks.json", None).await).await;
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(fetched).unwrap();
    let kid = jsonwebtoken::decode_header(&token).unwrap().kid.unwrap();
    let key = jsonwebtoken::DecodingKey::from_jwk(set.find(&kid).expect("kid is served")).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_audience(&["logless"]);
    validation.set_issuer(&[ISSUER]);
    let decoded =
        jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation).expect("verifies");
    assert_eq!(decoded.claims["sub"], "sp_test");

    // The control: a key set from a different store does not verify it.
    let other = harness("verify-other", true, 300);
    let set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(json(other.get("/auth/jwks.json", None).await).await).unwrap();
    assert!(set.find(&kid).is_none(), "another store has another kid");
}

#[tokio::test]
async fn a_rotation_shows_up_in_the_served_keys_and_changes_the_etag() {
    let h = harness("rotate", true, 300);
    let issuer = h.issuer.clone().unwrap();

    let first = h.get("/auth/jwks.json", None).await;
    let etag = header_of(&first, header::ETAG);
    assert_eq!(json(first).await["keys"].as_array().unwrap().len(), 1);

    // With a lead the new key is published ahead of signing: two keys served.
    let rotation = issuer.rotate(None, "test").unwrap();
    let second = h.get("/auth/jwks.json", Some(&etag)).await;
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "the old tag no longer matches"
    );
    let new_etag = header_of(&second, header::ETAG);
    assert_ne!(new_etag, etag);
    let kids: Vec<_> = json(second).await["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kids.len(), 2);
    assert_eq!(kids[0], rotation.kid, "newest first");

    // An emergency rotation unpublishes the others.
    issuer.rotate(Some(0), "test").unwrap();
    let third = h.get("/auth/jwks.json", Some(&new_etag)).await;
    assert_eq!(third.status(), StatusCode::OK);
    assert_eq!(json(third).await["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn if_none_match_gives_a_304_with_the_same_headers_and_no_body() {
    let h = harness("etag", true, 300);
    for path in PATHS {
        let first = h.get(path, None).await;
        let etag = header_of(&first, header::ETAG);

        for presented in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"nope\", {etag}"),
            "*".to_owned(),
        ] {
            let response = h.get(path, Some(&presented)).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_MODIFIED,
                "{path} {presented}"
            );
            assert_eq!(header_of(&response, header::ETAG), etag);
            assert!(header_of(&response, header::CACHE_CONTROL).starts_with("public"));
            assert!(response.headers().contains_key(header::DATE));
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(body.is_empty());
        }
        let response = h.get(path, Some("\"something-else\"")).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

#[test]
fn http_dates_are_imf_fixdate() {
    assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
    // A leap day, and the second before a year turns.
    assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
    assert_eq!(http_date(1_735_689_599), "Tue, 31 Dec 2024 23:59:59 GMT");
    assert_eq!(http_date(-1), "Wed, 31 Dec 1969 23:59:59 GMT");
}
