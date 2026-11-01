//! The provider registry end to end, with `mock-idp` as two real providers on
//! real sockets and the real store, audit sink, custody sink and routers.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use mock_idp::{spawn_mock_idp, ClientConfig, MockIdpConfig, MockIdpHandle, UserConfig};
use serde_json::{json, Value};
use tower::ServiceExt as _;

use super::*;
use crate::audit::{AuditConfig, AuditSink};
use crate::clock::{Clock, TestClock, Timestamp};
use crate::custody::{CustodySink, OidcUpstream};
use crate::http::admin::AdminState;
use crate::http::{AppState, HttpConfig};
use crate::keepalive::{RefreshOutcome, Upstream};
use crate::session::{CustodyId, SessionMap, SessionPolicy};
use crate::store::repo;
use crate::store::writer::{Command, Writer};
use crate::store::Reader;

const T0: Timestamp = Timestamp(1_700_000_000);
const ADMIN_KEY: &str = "an-admin-key-that-is-at-least-32-chars";
const REDIRECT: &str = "http://localhost:8080/auth/callback";
const SECRET_A: &str = "first-secret-value-3f9a";
const SECRET_B: &str = "second-secret-value-77c1";

static DB_SEQ: AtomicU32 = AtomicU32::new(0);

async fn idp(client_id: &str, secret: &str) -> MockIdpHandle {
    spawn_mock_idp(MockIdpConfig {
        clients: vec![ClientConfig {
            client_id: client_id.to_owned(),
            client_secret: Some(secret.to_owned()),
            redirect_uris: vec![REDIRECT.to_owned()],
        }],
        ..MockIdpConfig::default()
    })
    .await
    .unwrap()
}

struct Stack {
    public: Router,
    admin: Router,
    registry: Arc<ProviderRegistry>,
    reader: Arc<Reader>,
    writer: Writer,
    clock: Arc<dyn Clock>,
    /// Every response body the admin lane gave in this test.
    admin_bodies: Mutex<Vec<String>>,
    path: std::path::PathBuf,
}

impl Stack {
    async fn new(registry: ProviderRegistry) -> Stack {
        let path = std::env::temp_dir().join(format!(
            "session-broker-providers-{}-{}.sqlite3",
            std::process::id(),
            DB_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        Self::on(registry, path)
    }

    fn on(registry: ProviderRegistry, path: std::path::PathBuf) -> Stack {
        let keyfile = path.with_extension("key");
        let writer = Writer::spawn(crate::store::open(&path, &keyfile).unwrap());
        let reader = Arc::new(Reader::new(crate::store::open(&path, &keyfile).unwrap()));
        let registry = Arc::new(registry);
        let metrics = crate::telemetry::Metrics::new();
        let audit = AuditSink::new(writer.handle(), metrics.clone(), AuditConfig::default());
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(T0));
        let policy = SessionPolicy::default();
        let sessions = Arc::new(SessionMap::with_durability(policy, writer.handle()));
        let (schedule_tx, schedule_rx) = tokio::sync::mpsc::unbounded_channel();
        // The worker is not running here: tests drive `OidcUpstream` directly.
        std::mem::forget(schedule_rx);
        let state = AppState {
            sessions: sessions.clone(),
            clock: clock.clone(),
            config: Arc::new(HttpConfig::new("https://app.example.com", &policy).unwrap()),
            custody: Some(CustodySink::new(writer.handle(), schedule_tx)),
            audit: Some(audit.clone()),
            metrics: metrics.clone(),
            rate_limit: None,
            issuer: None,
        };
        let public = crate::http::router(state).layer(Extension(registry.clone()));
        let admin = crate::http::admin::router(AdminState {
            sessions,
            reader: reader.clone(),
            writer: writer.handle(),
            clock: clock.clone(),
            admin_key: Some(Arc::from(ADMIN_KEY)),
            audit: Some(audit),
            log: None,
            metrics,
            rate_limit: None,
            issuer: None,
            providers: registry.clone(),
        });
        Stack {
            public,
            admin,
            registry,
            reader,
            writer,
            clock,
            admin_bodies: Mutex::default(),
            path,
        }
    }

    async fn admin(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
            .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
            .unwrap();
        let response = self.admin.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let text = body_text(response).await;
        self.admin_bodies.lock().unwrap().push(text.clone());
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn add(&self, id: &str, handle: &MockIdpHandle, client_id: &str, secret: &str) {
        let (status, body) = self
            .admin(
                "POST",
                "/admin/providers",
                Some(json!({
                    "id": id,
                    "preset": "generic",
                    "display_name": format!("Provider {id}"),
                    "issuer_url": handle.base_url(),
                    "client_id": client_id,
                    "client_secret": secret,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> Response {
        let mut request = Request::builder().method("GET").uri(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.public
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn login_error(&self, uri: &str) -> (StatusCode, String) {
        let response = self.get(uri, None).await;
        let status = response.status();
        let body: Value = serde_json::from_str(&body_text(response).await).unwrap();
        (status, body["error"].as_str().unwrap().to_owned())
    }

    /// `/auth/login`, the IdP, `/auth/callback`. Answers the session cookie.
    async fn sign_in(&self, login_uri: &str) -> Result<String, String> {
        let (txn, code, state) = self.to_the_idp(login_uri).await;
        let response = self
            .get(
                &format!("/auth/callback?code={code}&state={state}"),
                Some(&txn),
            )
            .await;
        cookie(&response, "__Host-broker_session").ok_or_else(|| location(&response))
    }

    /// As far as the IdP's redirect back: `(txn cookie, code, state)`.
    async fn to_the_idp(&self, login_uri: &str) -> (String, String, String) {
        let login = self.get(login_uri, None).await;
        assert_eq!(login.status(), StatusCode::SEE_OTHER, "{login_uri}");
        let txn = cookie(&login, "__Host-broker_txn").unwrap();
        let back = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(location(&login))
            .send()
            .await
            .unwrap();
        assert_eq!(back.status(), reqwest::StatusCode::FOUND);
        let back = back.headers()[reqwest::header::LOCATION].to_str().unwrap();
        let url = Url::parse(back).unwrap();
        let param = |name: &str| {
            url.query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
                .unwrap()
        };
        (txn, param("code"), param("state"))
    }

    async fn session_sub(&self, session_cookie: &str) -> String {
        let response = self.get("/session", Some(session_cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&body_text(response).await).unwrap();
        body["sub"].as_str().unwrap().to_owned()
    }

    fn custody_of(&self, sub: &str) -> CustodyId {
        self.reader.with(|c| {
            CustodyId(
                c.query_row(
                    "SELECT custody_id FROM custody WHERE sub = ?1",
                    [sub],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
    }

    fn upstream(&self) -> OidcUpstream {
        OidcUpstream::new(
            self.registry.clone(),
            self.reader.clone(),
            self.writer.handle(),
            self.clock.clone(),
        )
    }
}

async fn body_text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn location(response: &Response) -> String {
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

fn cookie(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
}

async fn refresh_calls(handle: &MockIdpHandle) -> u64 {
    let state: Value = reqwest::get(format!("{}/__test__/state", handle.base_url()))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    state["counters"]["token_calls_by_grant"]["refresh_token"]
        .as_u64()
        .unwrap_or(0)
}

async fn two_providers() -> (Stack, MockIdpHandle, MockIdpHandle) {
    let a = idp("client-a", SECRET_A).await;
    let b = idp("client-b", SECRET_B).await;
    let stack = Stack::new(ProviderRegistry::empty(REDIRECT)).await;
    stack.add("a", &a, "client-a", SECRET_A).await;
    stack.add("b", &b, "client-b", SECRET_B).await;
    (stack, a, b)
}

#[tokio::test]
async fn a_login_completes_through_each_provider_on_that_providers_idp() {
    let (stack, a, b) = two_providers().await;

    let login = stack.get("/auth/login?provider=a", None).await;
    assert!(location(&login).starts_with(a.base_url()));
    let login = stack.get("/auth/login?provider=b", None).await;
    assert!(location(&login).starts_with(b.base_url()));

    // The mock IdPs insist on their own client id and secret at /token, so these
    // two completing also proves each callback used its own provider's client.
    let first = stack.sign_in("/auth/login?provider=a").await.unwrap();
    let second = stack.sign_in("/auth/login?provider=b").await.unwrap();
    assert_eq!(stack.session_sub(&first).await, "a|user-1");
    assert_eq!(stack.session_sub(&second).await, "b|user-1");
}

#[tokio::test]
async fn the_same_upstream_sub_on_two_providers_is_two_people() {
    let (stack, _a, _b) = two_providers().await;
    let first = stack.sign_in("/auth/login?provider=a").await.unwrap();
    let second = stack.sign_in("/auth/login?provider=b").await.unwrap();
    assert_ne!(
        stack.session_sub(&first).await,
        stack.session_sub(&second).await
    );

    // A role granted to one is not held by the other.
    let (status, body) = stack
        .admin(
            "POST",
            "/admin/user-grants",
            Some(json!({ "sub": "a|user-1", "roles": ["admin"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let grants = |sub: &str| {
        stack
            .reader
            .with(|c| repo::find_live_user_grants(c, sub))
            .unwrap()
    };
    assert_eq!(grants("a|user-1").len(), 1);
    assert_eq!(grants("b|user-1").len(), 0);
    assert_eq!(grants("user-1").len(), 0);

    // Listed apart too.
    let (_, people) = stack.admin("GET", "/admin/providers/a/people", None).await;
    assert_eq!(people["provider_id"], "a");
    assert_eq!(people["people"][0]["sub"], "a|user-1");
    assert_eq!(people["people"].as_array().unwrap().len(), 1);

    // Custody and session rows both record who issued them.
    let provider_of = |table: &str, sub: &str| -> String {
        stack.reader.with(|c| {
            c.query_row(
                &format!("SELECT provider_id FROM {table} WHERE sub = ?1"),
                [sub],
                |r| r.get(0),
            )
            .unwrap()
        })
    };
    assert_eq!(provider_of("custody", "b|user-1"), "b");
    stack.writer.handle().enqueue(Command::Ping);
    for _ in 0..200 {
        let written: i64 = stack.reader.with(|c| {
            c.query_row("SELECT COUNT(*) FROM session", [], |r| r.get(0))
                .unwrap()
        });
        if written == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(provider_of("session", "b|user-1"), "b");
}

#[tokio::test]
async fn the_secret_is_in_no_admin_response_no_audit_row_and_not_in_clear_on_disk() {
    let (stack, a, _b) = two_providers().await;
    const ROTATED: &str = "rotated-secret-value-a81d";

    stack.admin("GET", "/admin/providers", None).await;
    stack.admin("GET", "/admin/providers/a", None).await;
    stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "display_name": "Renamed" })),
        )
        .await;
    stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "client_secret": ROTATED })),
        )
        .await; // discovery only: the mock is not asked about the secret
    stack
        .admin(
            "POST",
            "/admin/providers/test",
            Some(json!({ "issuer_url": a.base_url() })),
        )
        .await;
    // Every refusal path that had a secret in the request.
    stack
        .admin(
            "POST",
            "/admin/providers",
            Some(json!({
                "id": "a", "preset": "generic", "display_name": "x",
                "issuer_url": a.base_url(), "client_id": "c", "client_secret": SECRET_A,
            })),
        )
        .await;
    stack
        .admin(
            "POST",
            "/admin/providers",
            Some(json!({
                "id": "c", "preset": "generic", "display_name": "x",
                "issuer_url": "http://198.51.100.1", "client_id": "c", "client_secret": SECRET_A,
            })),
        )
        .await;
    stack.admin("DELETE", "/admin/providers/b", None).await;
    stack.admin("GET", "/admin/audit?limit=100", None).await;

    let secrets = [SECRET_A, SECRET_B, ROTATED];
    let bodies = stack.admin_bodies.lock().unwrap().clone();
    assert!(bodies.len() >= 9);
    for body in &bodies {
        for secret in secrets {
            assert!(!body.contains(secret), "secret in a response: {body}");
        }
        assert!(
            !body.contains("client_secret"),
            "field in a response: {body}"
        );
    }

    let audit: Vec<String> = stack.reader.with(|c| {
        c.prepare("SELECT action || ' ' || COALESCE(detail, '') FROM audit WHERE action LIKE 'provider.%'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    });
    // Two creates, two updates, one delete. A refused create wrote no row.
    assert_eq!(audit.len(), 5, "{audit:?}");
    assert!(
        audit
            .iter()
            .any(|row| row.contains(r#""secret_changed":true"#)
                && row.starts_with("provider.updated"))
    );
    for row in &audit {
        for secret in secrets {
            assert!(!row.contains(secret), "secret in an audit row: {row}");
        }
    }

    // On disk it is sealed, and a deleted provider's seal is gone.
    let sealed = |id: &str| -> Vec<u8> {
        stack.reader.with(|c| {
            c.query_row(
                "SELECT client_secret_sealed FROM identity_provider WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap()
        })
    };
    let stored = sealed("a");
    assert!(!stored.is_empty());
    assert!(!stored
        .windows(ROTATED.len())
        .any(|w| w == ROTATED.as_bytes()));
    assert!(sealed("b").is_empty());
}

#[tokio::test]
async fn a_disabled_provider_refuses_a_new_login_and_leaves_the_chooser() {
    let (stack, _a, _b) = two_providers().await;

    let in_flight = stack.to_the_idp("/auth/login?provider=a").await;
    let (status, body) = stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], false);

    assert_eq!(
        stack.login_error("/auth/login?provider=a").await,
        (StatusCode::FORBIDDEN, "provider_disabled".to_owned())
    );
    let choices = body_text(stack.get("/auth/providers", None).await).await;
    let choices: Value = serde_json::from_str(&choices).unwrap();
    assert_eq!(
        choices,
        json!({ "providers": [{ "id": "b", "display_name": "Provider b" }] })
    );

    // A login already at the IdP does not finish on it either.
    let (txn, code, state) = in_flight;
    let response = stack
        .get(
            &format!("/auth/callback?code={code}&state={state}"),
            Some(&txn),
        )
        .await;
    assert!(cookie(&response, "__Host-broker_session").is_none());
    assert!(location(&response).contains("error=oauth_error"));

    // Enabled again, login works, and with one disabled the param was optional.
    let only = stack.sign_in("/auth/login").await.unwrap();
    assert_eq!(stack.session_sub(&only).await, "b|user-1");
    stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "enabled": true })),
        )
        .await;
    assert!(stack.sign_in("/auth/login?provider=a").await.is_ok());
}

#[tokio::test]
async fn keepalive_refreshes_on_the_provider_that_issued_the_grant() {
    let (stack, a, b) = two_providers().await;
    stack.sign_in("/auth/login?provider=a").await.unwrap();
    stack.sign_in("/auth/login?provider=b").await.unwrap();
    let upstream = stack.upstream();

    let outcome = upstream.refresh(&stack.custody_of("b|user-1")).await;
    assert!(
        matches!(outcome, RefreshOutcome::Success { .. }),
        "{outcome:?}"
    );
    assert_eq!(refresh_calls(&a).await, 0);
    assert_eq!(refresh_calls(&b).await, 1);

    let outcome = upstream.refresh(&stack.custody_of("a|user-1")).await;
    assert!(
        matches!(outcome, RefreshOutcome::Success { .. }),
        "{outcome:?}"
    );
    assert_eq!(refresh_calls(&a).await, 1);
    assert_eq!(refresh_calls(&b).await, 1);

    // Disabled: no new login, and the existing grant still renews.
    stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "enabled": false })),
        )
        .await;
    let custody = stack.custody_of("a|user-1");
    let outcome = upstream.refresh(&custody).await;
    assert!(
        matches!(outcome, RefreshOutcome::Success { .. }),
        "{outcome:?}"
    );
    assert_eq!(refresh_calls(&a).await, 2);

    // Revoked at the IdP while disabled: the ordinary permanent outcome, which is
    // what the upstream-revoked policy acts on.
    reqwest::Client::new()
        .post(format!("{}/__test__/revoke-refresh", a.base_url()))
        .json(&json!({ "subject": "user-1" }))
        .send()
        .await
        .unwrap();
    assert!(matches!(
        upstream.refresh(&custody).await,
        RefreshOutcome::Permanent
    ));

    // Deleted: permanent, and no call goes anywhere.
    let (status, _) = stack.admin("DELETE", "/admin/providers/b", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(matches!(
        upstream.refresh(&stack.custody_of("b|user-1")).await,
        RefreshOutcome::Permanent
    ));
    assert_eq!(refresh_calls(&b).await, 1);
}

#[tokio::test]
async fn a_broker_boots_with_zero_providers_and_refuses_login_by_name() {
    let config = OidcConfig {
        issuer_url: None,
        client_id: None,
        client_secret: None,
        scopes: Vec::new(),
        redirect_uri: None,
    };
    let registry = ProviderRegistry::boot(&config, Vec::new(), REDIRECT.to_owned())
        .await
        .expect("no provider is a valid boot");
    let stack = Stack::new(registry).await;

    assert_eq!(
        stack.login_error("/auth/login").await,
        (StatusCode::SERVICE_UNAVAILABLE, "no_providers".to_owned())
    );
    assert_eq!(
        stack.login_error("/auth/login?provider=nope").await,
        (StatusCode::NOT_FOUND, "unknown_provider".to_owned())
    );
    let choices = body_text(stack.get("/auth/providers", None).await).await;
    assert_eq!(choices, r#"{"providers":[]}"#);
    let (status, list) = stack.admin("GET", "/admin/providers", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list, json!({ "redirect_uri": REDIRECT, "providers": [] }));

    // A grant from a config provider since removed waits; it is not declared dead.
    let idp_a = idp("client-a", SECRET_A).await;
    stack.add("a", &idp_a, "client-a", SECRET_A).await;
    assert!(matches!(
        stack.registry.client_for_refresh(DEFAULT_PROVIDER).await,
        RefreshClient::Unavailable(_)
    ));
}

#[tokio::test]
async fn with_several_enabled_the_choice_is_required_and_with_one_it_is_not() {
    let (stack, _a, _b) = two_providers().await;
    assert_eq!(
        stack.login_error("/auth/login").await,
        (StatusCode::BAD_REQUEST, "provider_required".to_owned())
    );
    stack.admin("DELETE", "/admin/providers/a", None).await;
    assert_eq!(
        stack.login_error("/auth/login?provider=a").await,
        (StatusCode::NOT_FOUND, "unknown_provider".to_owned())
    );
    let only = stack.sign_in("/auth/login").await.unwrap();
    assert_eq!(stack.session_sub(&only).await, "b|user-1");
}

#[tokio::test]
async fn an_iss_parameter_must_name_the_provider_the_login_started_on() {
    let (stack, a, b) = two_providers().await;

    let (txn, code, state) = stack.to_the_idp("/auth/login?provider=a").await;
    let wrong = stack
        .get(
            &format!(
                "/auth/callback?code={code}&state={state}&iss={}",
                b.base_url()
            ),
            Some(&txn),
        )
        .await;
    assert!(cookie(&wrong, "__Host-broker_session").is_none());
    assert!(location(&wrong).contains("error=oauth_error"));

    let (txn, code, state) = stack.to_the_idp("/auth/login?provider=a").await;
    let right = stack
        .get(
            &format!(
                "/auth/callback?code={code}&state={state}&iss={}",
                a.base_url()
            ),
            Some(&txn),
        )
        .await;
    assert!(cookie(&right, "__Host-broker_session").is_some());
}

#[tokio::test]
async fn a_login_in_flight_survives_its_provider_being_edited() {
    let (stack, _a, _b) = two_providers().await;
    let (txn, code, state) = stack.to_the_idp("/auth/login?provider=a").await;
    // The scope change forces a new client.
    let (status, _) = stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "scopes": ["openid", "offline_access", "email"] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let response = stack
        .get(
            &format!("/auth/callback?code={code}&state={state}"),
            Some(&txn),
        )
        .await;
    assert!(cookie(&response, "__Host-broker_session").is_some());
}

#[tokio::test]
async fn a_put_without_a_secret_keeps_the_stored_one_and_a_wrong_new_one_is_used() {
    let (stack, _a, _b) = two_providers().await;
    let (status, body) = stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(
                json!({ "client_id": "client-a", "scopes": ["openid", "offline_access", "email"] }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["has_secret"], true);
    // The mock refuses a wrong secret at /token, so this completing is the proof.
    assert!(stack.sign_in("/auth/login?provider=a").await.is_ok());

    let (status, _) = stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "client_secret": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "client_secret": "not-what-the-idp-holds" })),
        )
        .await;
    let refused = stack.sign_in("/auth/login?provider=a").await.unwrap_err();
    assert!(refused.contains("error=oauth_error"));
}

#[tokio::test]
async fn an_issuer_must_be_https_off_loopback_and_match_discovery_exactly() {
    let a = idp("client-a", SECRET_A).await;
    let stack = Stack::new(ProviderRegistry::empty(REDIRECT)).await;

    let test = |issuer: String| {
        let stack = &stack;
        async move {
            stack
                .admin(
                    "POST",
                    "/admin/providers/test",
                    Some(json!({ "issuer_url": issuer })),
                )
                .await
        }
    };

    let (status, found) = test(a.base_url().to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found["ok"], true);
    assert_eq!(found["issuer"], a.base_url());
    assert_eq!(found["token_endpoint"], format!("{}/token", a.base_url()));
    assert!(found["jwks_keys"].as_u64().unwrap() >= 1);

    // Unsaved.
    let (_, list) = stack.admin("GET", "/admin/providers", None).await;
    assert_eq!(list["providers"], json!([]));

    let (_, off_loopback) = test("http://idp.example.com".to_owned()).await;
    assert_eq!(off_loopback["ok"], false);
    assert_eq!(off_loopback["failure"], "issuer_not_https");

    // The document says no trailing slash; Auth0-style equality is byte exact.
    let (_, mismatch) = test(format!("{}/", a.base_url())).await;
    assert_eq!(mismatch["failure"], "issuer_mismatch", "{mismatch}");

    let (_, status_failure) = test(format!("{}/nothing-here", a.base_url())).await;
    assert_eq!(status_failure["failure"], "http_status");

    let port = {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        held.local_addr().unwrap().port()
    };
    let (_, unreachable) = test(format!("http://127.0.0.1:{port}")).await;
    assert_eq!(unreachable["failure"], "unreachable");

    // The same rules guard a save.
    let save = |issuer: String, enabled: bool| {
        json!({
            "id": "x", "preset": "generic", "display_name": "X", "issuer_url": issuer,
            "client_id": "c", "client_secret": "s", "enabled": enabled,
        })
    };
    let (status, body) = stack
        .admin(
            "POST",
            "/admin/providers",
            Some(save("http://idp.example.com".to_owned(), false)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_issuer");
    assert_eq!(body["failure"], "issuer_not_https");

    let (status, body) = stack
        .admin(
            "POST",
            "/admin/providers",
            Some(save(format!("{}/", a.base_url()), true)),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "discovery_failed");
    assert_eq!(body["failure"], "issuer_mismatch");
    let (_, list) = stack.admin("GET", "/admin/providers", None).await;
    assert_eq!(
        list["providers"],
        json!([]),
        "a failed discovery saves nothing"
    );

    // Saved disabled it is not probed; enabling it is.
    let (status, _) = stack
        .admin(
            "POST",
            "/admin/providers",
            Some(save(format!("{}/", a.base_url()), false)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = stack
        .admin(
            "PUT",
            "/admin/providers/x",
            Some(json!({ "enabled": true })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["failure"], "issuer_mismatch");
}

#[tokio::test]
async fn a_providers_people_cannot_move_to_another_issuer() {
    let (stack, a, b) = two_providers().await;
    stack.sign_in("/auth/login?provider=a").await.unwrap();

    // With someone under it, the issuer is fixed.
    let (status, body) = stack
        .admin(
            "PUT",
            "/admin/providers/a",
            Some(json!({ "issuer_url": b.base_url() })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "issuer_locked");

    // Deleted, the id can only come back on the same issuer.
    assert_eq!(
        stack.admin("DELETE", "/admin/providers/a", None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        stack.admin("GET", "/admin/providers/a", None).await.0,
        StatusCode::NOT_FOUND
    );
    let again = |issuer: &str| {
        json!({
            "id": "a", "preset": "generic", "display_name": "Again", "issuer_url": issuer,
            "client_id": "client-a", "client_secret": SECRET_A,
        })
    };
    let (status, body) = stack
        .admin("POST", "/admin/providers", Some(again(b.base_url())))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "provider_id_retired");
    let (status, _) = stack
        .admin("POST", "/admin/providers", Some(again(a.base_url())))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(stack.sign_in("/auth/login?provider=a").await.is_ok());

    // A grant spelled for an id nobody has registered reserves that id too.
    stack
        .admin(
            "POST",
            "/admin/user-grants",
            Some(json!({ "sub": "later|123", "roles": ["admin"] })),
        )
        .await;
    let (status, body) = stack
        .admin(
            "POST",
            "/admin/providers",
            Some(json!({
                "id": "later", "preset": "generic", "display_name": "Later",
                "issuer_url": a.base_url(), "client_id": "client-a", "client_secret": SECRET_A,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "provider_id_retired");
}

#[tokio::test]
async fn the_config_provider_is_default_read_only_and_keeps_its_spelling() {
    let a = idp("client-a", SECRET_A).await;
    let d = idp("client-d", "config-secret").await;
    let toml_free = crate::config::OidcConfig {
        issuer_url: Some(d.base_url().to_owned()),
        client_id: Some("client-d".to_owned()),
        client_secret: Some(ClientSecret::new("config-secret".to_owned())),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        redirect_uri: Some(REDIRECT.to_owned()),
    };
    let registry = ProviderRegistry::boot(&toml_free, Vec::new(), REDIRECT.to_owned())
        .await
        .unwrap();
    let stack = Stack::new(registry).await;

    let only = stack.sign_in("/auth/login").await.unwrap();
    assert_eq!(stack.session_sub(&only).await, "user-1");

    let (status, view) = stack.admin("GET", "/admin/providers/default", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["read_only"], true);
    assert_eq!(view["preset"], "config");
    assert_eq!(view["created_at"], Value::Null);
    assert!(!view.to_string().contains("config-secret"));

    assert_eq!(
        stack
            .admin(
                "PUT",
                "/admin/providers/default",
                Some(json!({ "enabled": false }))
            )
            .await
            .1["error"],
        "read_only_provider"
    );
    assert_eq!(
        stack
            .admin("DELETE", "/admin/providers/default", None)
            .await
            .1["error"],
        "read_only_provider"
    );
    for reserved in ["default", "test"] {
        let (status, body) = stack
            .admin(
                "POST",
                "/admin/providers",
                Some(json!({
                    "id": reserved, "preset": "generic", "display_name": "X",
                    "issuer_url": a.base_url(), "client_id": "c", "client_secret": "s",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "reserved_id");
    }

    // The config provider's grant renews on the config provider.
    let outcome = stack.upstream().refresh(&stack.custody_of("user-1")).await;
    assert!(
        matches!(outcome, RefreshOutcome::Success { .. }),
        "{outcome:?}"
    );
    assert_eq!(refresh_calls(&d).await, 1);
}

/// `default` keeps the upstream spelling, so its upstream sub `entra|123` would
/// otherwise BE provider `entra`'s person 123, and hold that person's grants.
#[tokio::test]
async fn a_config_provider_subject_spelled_like_another_providers_person_is_refused() {
    let a = idp("client-a", SECRET_A).await;
    let d = spawn_mock_idp(MockIdpConfig {
        clients: vec![ClientConfig {
            client_id: "client-d".to_owned(),
            client_secret: Some("config-secret".to_owned()),
            redirect_uris: vec![REDIRECT.to_owned()],
        }],
        users: vec![UserConfig {
            subject: "entra|123".to_owned(),
            email: "x@example.test".to_owned(),
            name: "X".to_owned(),
        }],
        ..MockIdpConfig::default()
    })
    .await
    .unwrap();
    let config = OidcConfig {
        issuer_url: Some(d.base_url().to_owned()),
        client_id: Some("client-d".to_owned()),
        client_secret: Some(ClientSecret::new("config-secret".to_owned())),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        redirect_uri: Some(REDIRECT.to_owned()),
    };
    let registry = ProviderRegistry::boot(&config, Vec::new(), REDIRECT.to_owned())
        .await
        .unwrap();
    let stack = Stack::new(registry).await;
    stack.add("entra", &a, "client-a", SECRET_A).await;

    let refused = stack
        .sign_in("/auth/login?provider=default")
        .await
        .unwrap_err();
    assert!(refused.contains("error=oauth_error"));
    let held: i64 = stack.reader.with(|c| {
        c.query_row("SELECT COUNT(*) FROM custody", [], |r| r.get(0))
            .unwrap()
    });
    assert_eq!(held, 0, "no grant is taken for a refused person");
    assert!(!stack.registry.subject_collides("auth0|123"));
    assert!(!stack.registry.subject_collides("user-1"));
}

#[tokio::test]
async fn a_stored_provider_survives_a_restart_and_connects_on_first_use() {
    let a = idp("client-a", SECRET_A).await;
    let stack = Stack::new(ProviderRegistry::empty(REDIRECT)).await;
    stack.add("a", &a, "client-a", SECRET_A).await;

    let rows = stack.reader.with(repo::list_providers).unwrap();
    assert_eq!(rows.len(), 1);
    let config = OidcConfig {
        issuer_url: None,
        client_id: None,
        client_secret: None,
        scopes: Vec::new(),
        redirect_uri: None,
    };
    let reborn = ProviderRegistry::boot(&config, rows, REDIRECT.to_owned())
        .await
        .unwrap();
    assert!(
        reborn.connected_client("a").is_none(),
        "lazy, so boot needs no IdP"
    );

    let restarted = Stack::on(reborn, stack.path.clone());
    let session = restarted.sign_in("/auth/login?provider=a").await.unwrap();
    assert_eq!(restarted.session_sub(&session).await, "a|user-1");
}

#[test]
fn issuer_forms() {
    assert!(check_issuer_url("https://login.microsoftonline.com/t/v2.0").is_ok());
    assert!(check_issuer_url("https://tenant.auth0.com/").is_ok());
    assert!(check_issuer_url("http://127.0.0.1:9090").is_ok());
    assert!(check_issuer_url("http://localhost:9090").is_ok());
    assert!(check_issuer_url("http://[::1]:9090").is_ok());
    for (issuer, failure) in [
        ("http://idp.example.com", "issuer_not_https"),
        ("http://127.0.0.1.example.com", "issuer_not_https"),
        ("ftp://idp.example.com", "issuer_not_https"),
        ("not a url", "invalid_url"),
        ("https://user:pw@idp.example.com", "invalid_url"),
        ("https://idp.example.com?x=1", "invalid_url"),
        ("https://idp.example.com#f", "invalid_url"),
    ] {
        assert_eq!(
            check_issuer_url(issuer).unwrap_err().failure,
            failure,
            "{issuer}"
        );
    }
}

#[test]
fn a_person_is_spelled_by_provider_and_default_keeps_its_spelling() {
    use crate::oauth::person_subject;
    assert_eq!(person_subject("entra", "123"), "entra|123");
    assert_eq!(person_subject("default", "123"), "123");
    assert_eq!(person_subject("default", "auth0|123"), "auth0|123");
}

#[test]
fn the_provider_secret_is_resealed_with_the_rest() {
    use crate::store::crypto;
    let conn = crate::store::open_in_memory().unwrap();
    let new = repo::NewProvider {
        id: "a".to_owned(),
        preset: "generic".to_owned(),
        display_name: "A".to_owned(),
        issuer_url: "https://idp.example.com".to_owned(),
        client_id: "c".to_owned(),
        client_secret: ClientSecret::new("shh".to_owned()),
        scopes: vec!["openid".to_owned()],
        enabled: true,
    };
    assert!(repo::insert_provider(&conn, &new, T0).unwrap());
    // Tombstones have nothing to reseal, and must not count as unreadable.
    let gone = repo::NewProvider {
        id: "b".to_owned(),
        ..new.clone()
    };
    assert!(repo::insert_provider(&conn, &gone, T0).unwrap());
    assert!(repo::delete_provider(&conn, "b", T0).unwrap());

    let rotated = crypto::rotated_for_test();
    let report = repo::reseal_all_with(&conn, &rotated).unwrap();
    assert_eq!(report.identity_providers.resealed, 1);
    assert_eq!(report.identity_providers.failed, 0);
    let sealed: Vec<u8> = conn
        .query_row(
            "SELECT client_secret_sealed FROM identity_provider WHERE id = 'a'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(crypto::key_id_of(&sealed), Some(rotated.active_id()));
}
