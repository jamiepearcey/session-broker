//! `POST /internal/token` — the backend lane (INV-11, ADR-0007).
//!
//! This is how a backend service acts on a user's behalf without the upstream
//! access token ever passing through browser JS. It is the seam every
//! downstream service authenticates against, so its refusals are as much a
//! part of the contract as its successes.
//!
//! **Dual authentication, and neither half is sufficient.**
//!
//! * A static `Authorization: Bearer <broker_api_key>` proves the caller is a
//!   backend this deployment trusts. Provisioned out of band. On its own it
//!   yields nothing — a stolen key cannot name a user.
//! * A live session token in the body proves *which* user. On its own it also
//!   yields nothing, which is the point: a session cookie stolen by XSS cannot
//!   be exchanged for an upstream token, because the browser does not have the
//!   API key and must not.
//!
//! The endpoint binds to its own listener (`internal_bind_addr`), so in a
//! hardened deployment it is not reachable from the internet at all. That is a
//! topology decision, not something this module can enforce — hence dual auth
//! regardless.
//!
//! **No inline refresh (INV-8/ADR-0003).** If the custodied access token has
//! expired, this returns `custody_unavailable` rather than calling the IdP.
//! Refreshing here would put upstream latency on a backend's request path and
//! reintroduce exactly the coupling the keepalive worker exists to remove.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::session::{CustodyStatus, SessionMap};
use crate::store::repo;
use crate::store::Reader;
use crate::token::TokenHash;

/// State for the internal listener. Deliberately a different type from
/// `http::AppState`: this lane needs the store and the API key, and must not
/// accidentally acquire cookie-issuing powers.
#[derive(Clone)]
pub struct InternalState {
    pub sessions: Arc<SessionMap>,
    pub reader: Arc<Reader>,
    pub clock: Arc<dyn Clock>,
    /// The BOOTSTRAP key from config, compared in constant time.
    ///
    /// Not the only way in: issued keys live in `api_key` and are what services
    /// should use. This one exists so the first issued key can be created, and
    /// as a break-glass credential — it cannot be revoked without a deploy.
    pub api_key: Option<Arc<str>>,
    /// For recording key usage. Optional because the lane must still answer if
    /// the writer is unavailable — "when was this key last used" is useful, not
    /// load-bearing.
    pub writer: Option<crate::store::writer::WriterHandle>,
    /// When each key's usage was last recorded, so `/authz` — which runs on
    /// EVERY request through the edge — does not turn into one database write
    /// per HTTP request. See [`TOUCH_INTERVAL`].
    pub last_touch: Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    /// Counters for this lane and for `/authz`, which shares this state.
    pub metrics: Arc<crate::telemetry::Metrics>,
    /// `None` in the unit tests that build a lane with no store behind it.
    pub audit: Option<crate::audit::AuditSink>,
}

/// How often a key's `last_used_at` is refreshed.
///
/// The column answers "is anything still using this key?", which an operator
/// reads before revoking. Minute granularity answers that perfectly well, and
/// the alternative — a write per request — would make the busiest lane in the
/// deployment the heaviest writer in it.
const TOUCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// How a backend authenticated, if it did.
enum BackendAuth {
    /// A key issued through the admin lane. Carries its id so usage can be
    /// recorded and so logs name the holder rather than the secret.
    Issued(String),
    Bootstrap,
    /// No key material configured at all — the lane is off.
    Disabled,
    Refused,
}

/// Whether a request carries a recognised backend credential.
///
/// Shared with the `/authz` lane so the edge authenticates exactly the way every
/// other backend does — one answer to "is this a service we trust", not two that
/// can drift apart.
pub(crate) fn backend_is_authenticated(state: &InternalState, headers: &HeaderMap) -> bool {
    let Some(presented) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    match authenticate_backend(state, presented) {
        BackendAuth::Issued(key_id) => {
            record_use(state, &key_id);
            true
        }
        BackendAuth::Bootstrap => true,
        BackendAuth::Disabled | BackendAuth::Refused => false,
    }
}

/// Record that an issued key was used, at most once per [`TOUCH_INTERVAL`].
///
/// Without this the console reports `used: never` for the edge's key while it
/// authenticates every request in the deployment — and an operator reading that
/// would reasonably revoke it as dead, taking the whole gateway down.
pub(crate) fn record_use(state: &InternalState, key_id: &str) {
    let Some(writer) = &state.writer else { return };
    let now = std::time::Instant::now();

    {
        let Ok(mut seen) = state.last_touch.lock() else {
            return;
        };
        match seen.get(key_id) {
            Some(at) if now.duration_since(*at) < TOUCH_INTERVAL => return,
            _ => seen.insert(key_id.to_owned(), now),
        };
    }

    let _ = writer.enqueue_touch(key_id, state.clock.now());
}

fn authenticate_backend(state: &InternalState, presented: &str) -> BackendAuth {
    let hash = crate::http::admin::hash_secret(presented);
    match state
        .reader
        .with(|conn| repo::find_live_api_key(conn, &hash))
    {
        Ok(Some(row)) => return BackendAuth::Issued(row.key_id),
        Ok(None) => {}
        // A store failure must not silently promote the bootstrap key into the
        // only working credential, but nor should it lock everyone out while
        // one is configured — so fall through and let the bootstrap check
        // decide, and say loudly that the issued-key check did not happen.
        Err(e) => {
            tracing::error!(error = %e, "internal lane: issued-key lookup failed");
        }
    }

    match state.api_key.as_deref() {
        Some(expected) if key_matches(presented, expected) => BackendAuth::Bootstrap,
        Some(_) => BackendAuth::Refused,
        // Nothing configured and no issued key matched. If any issued keys
        // exist this is a refusal, not a disabled lane — but we cannot tell
        // those apart cheaply, and "disabled" is the safer thing to report
        // when there is no bootstrap key: it points an operator at
        // configuration rather than at the caller.
        None => BackendAuth::Disabled,
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// The raw session cookie value, forwarded by the backend. Hashed here;
    /// never stored.
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub sub: String,
    pub expires_at: i64,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: &'static str,
}

fn refuse(status: StatusCode, error: &'static str, detail: &'static str) -> Response {
    (status, Json(ErrorBody { error, detail })).into_response()
}

pub fn router(state: InternalState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route("/internal/token", axum::routing::post(exchange))
        .with_state(state)
}

/// Constant-time comparison, so a caller cannot recover the key one byte at a
/// time from response timing. `subtle`-free: the key is short and this is a
/// simple accumulate-differences loop, which is what `ct_eq` would do anyway.
pub(crate) fn key_matches(presented: &str, expected: &str) -> bool {
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    // Length is not secret (and leaking it via early return changes nothing an
    // attacker cannot measure by sending different lengths), but the byte
    // comparison below must not short-circuit.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A refusal, as one value.
///
/// The lane's refusals are as much a part of its contract as its successes, so
/// they are produced in one place and recorded in one place. Threading them back
/// as a value rather than returning a `Response` from eight scattered points is
/// what makes "every refusal is counted and audited" true by construction
/// instead of by remembering.
struct Refusal {
    status: StatusCode,
    error: &'static str,
    detail: &'static str,
}

impl Refusal {
    fn new(status: StatusCode, error: &'static str, detail: &'static str) -> Refusal {
        Refusal {
            status,
            error,
            detail,
        }
    }
}

async fn exchange(
    State(state): State<InternalState>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Response {
    let now = state.clock.now();
    let mut key_id: Option<String> = None;
    let mut sid: Option<String> = None;
    let mut subject: Option<String> = None;

    let outcome = exchange_inner(
        &state,
        &headers,
        &request,
        &mut key_id,
        &mut sid,
        &mut subject,
    );

    match outcome {
        Ok(response) => {
            state.metrics.record_token_exchange("granted");
            if let Some(sink) = &state.audit {
                // Coalesced per (key_id, sid): the audit fact is "this backend
                // acted for this user this afternoon", not the ten thousand
                // times it did so. Refusals below are never coalesced.
                let key = key_id.clone().unwrap_or_else(|| "bootstrap".to_owned());
                let session = sid.clone().unwrap_or_default();
                if sink.should_record_exchange(&key, &session, now) {
                    let mut event = crate::audit::Event::new(
                        crate::audit::action::TOKEN_EXCHANGED,
                        crate::audit::Outcome::Success,
                        crate::audit::ActorKind::Backend,
                        now,
                    )
                    .actor_id(key.clone())
                    .key_id(key);
                    if let Some(sid) = &sid {
                        event = event.sid(sid.clone());
                    }
                    if let Some(sub) = &subject {
                        event = event.subject(sub.clone());
                    }
                    sink.record(event);
                }
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(refusal) => {
            state.metrics.record_token_exchange(refusal.error);
            if let Some(sink) = &state.audit {
                let mut event = crate::audit::Event::new(
                    crate::audit::action::TOKEN_REFUSED,
                    crate::audit::Outcome::Failure,
                    crate::audit::ActorKind::Backend,
                    now,
                )
                .reason(refusal.error);
                if let Some(key) = &key_id {
                    event = event.actor_id(key.clone()).key_id(key.clone());
                }
                if let Some(sid) = &sid {
                    event = event.sid(sid.clone());
                }
                sink.record(event);
            }
            refuse(refusal.status, refusal.error, refusal.detail)
        }
    }
}

fn exchange_inner(
    state: &InternalState,
    headers: &HeaderMap,
    request: &TokenRequest,
    key_id: &mut Option<String>,
    sid_out: &mut Option<String>,
    subject_out: &mut Option<String>,
) -> Result<TokenResponse, Refusal> {
    // --- half one: is this a backend we trust? -----------------------------
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(presented) = presented else {
        return Err(Refusal::new(
            StatusCode::UNAUTHORIZED,
            "missing_api_key",
            "This lane requires a broker API key in addition to a session token.",
        ));
    };

    // Two ways a key can be valid, and the distinction is deliberate:
    //
    //  * the ISSUED keys in `api_key`, which an operator can name, rotate and
    //    revoke from the console without a restart — the normal case;
    //  * the single BOOTSTRAP key from config, which exists so the first key
    //    can be issued at all (and as a break-glass credential if the store is
    //    unreadable). It cannot be revoked without a deploy, which is exactly
    //    why it should not be what services use day to day.
    //
    // Issued keys are checked first so that revoking one takes effect even in a
    // deployment that still has the bootstrap key configured.
    match authenticate_backend(state, presented) {
        BackendAuth::Issued(id) => {
            record_use(state, &id);
            *key_id = Some(id);
        }
        BackendAuth::Bootstrap => {
            tracing::debug!("internal token lane authenticated with the bootstrap key");
        }
        BackendAuth::Disabled => {
            return Err(Refusal::new(
                StatusCode::NOT_IMPLEMENTED,
                "lane_disabled",
                "No broker API keys are configured, so the internal token lane is disabled.",
            ))
        }
        BackendAuth::Refused => {
            return Err(Refusal::new(
                StatusCode::UNAUTHORIZED,
                "bad_api_key",
                "The broker API key was not recognised.",
            ))
        }
    }

    // --- half two: which user, and is their session live? ------------------
    let now = state.clock.now();
    let hash = TokenHash::of(&request.session_token);
    let resolution = state.sessions.resolve(&hash, now);

    // The sid is recorded even on the refusal paths below, so the audit trail
    // can answer "which session was a backend refused for" — but it is read
    // from the broker's own map, never from anything the caller supplied.
    *sid_out = state.sessions.sid_for_hash(&hash).map(|s| s.0);

    // `authenticates()` is `Active` only. A stale-but-refreshable generation
    // deliberately does NOT authenticate a resource call: the browser must
    // refresh first, so that a tab which has been asleep cannot keep driving
    // backends on a generation it has not renewed.
    let not_active = Refusal::new(
        StatusCode::UNAUTHORIZED,
        "session_not_active",
        "The presented session token does not authenticate resource access.",
    );
    if !resolution.authenticates() {
        return Err(not_active);
    }

    let Some(meta) = state.sessions.meta_for(&hash) else {
        return Err(not_active);
    };
    *subject_out = Some(meta.sub.clone());

    let Some(custody_id) = state.sessions.custody_for(&hash) else {
        return Err(not_active);
    };

    if meta.custody == CustodyStatus::Dead {
        return Err(Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_revoked",
            "The upstream grant behind this session has been revoked.",
        ));
    }

    let loaded = state
        .reader
        .with(|conn| repo::load_custody(conn, &custody_id));

    let row = match loaded {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "custody_unavailable",
                "No upstream grant is held for this session.",
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "internal token lane: custody read failed");
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "custody_unavailable",
                "The upstream grant could not be read.",
            ));
        }
    };

    // Expired and NOT refreshed here, on purpose (INV-8). The keepalive worker
    // renews on its own schedule; a backend that sees this should retry, not
    // treat it as an auth failure.
    if now.secs() >= row.access_exp.secs() {
        return Err(Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "custody_unavailable",
            "The custodied access token has expired and has not yet been renewed.",
        ));
    }

    let Ok(access_token) = String::from_utf8(row.access_tok) else {
        tracing::error!("internal token lane: stored access token is not valid UTF-8");
        return Err(Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "custody_unavailable",
            "The stored access token could not be decoded.",
        ));
    };

    Ok(TokenResponse {
        access_token,
        sub: row.sub,
        expires_at: row.access_exp.secs(),
        scope: row.scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{TestClock, Timestamp};
    use crate::session::{CustodyId, SessionPolicy, Sid};
    use crate::store::writer::Writer;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const T0: Timestamp = Timestamp(1_700_000_000);
    const API_KEY: &str = "backend-key-provisioned-out-of-band";

    struct Harness {
        router: Router,
        token: String,
        _writer: Writer,
    }

    fn harness() -> Harness {
        let conn = crate::store::open_in_memory().unwrap();
        let reader_conn = crate::store::open_in_memory().unwrap();
        let writer = Writer::spawn(conn);

        let sessions = Arc::new(SessionMap::new(SessionPolicy::default()));
        let custody = CustodyId("cust-1".to_owned());
        let issued = sessions.create(
            Sid("sid-1".to_owned()),
            custody.clone(),
            "alice".to_owned(),
            T0,
        );

        // The custody row lives in the reader's database here: these two
        // in-memory connections are separate databases, and what this test
        // exercises is the LANE's logic, not the store's — which has its own
        // round-trip coverage.
        repo::insert_custody(
            &reader_conn,
            &repo::CustodyRow {
                custody_id: custody,
                sub: "alice".to_owned(),
                refresh_tok: b"refresh".to_vec(),
                access_tok: b"upstream-access-token".to_vec(),
                access_exp: T0.plus_secs(300),
                scope: Some("openid profile".to_owned()),
                status: CustodyStatus::Ok,
                next_refresh: T0.plus_secs(180),
                fail_count: 0,
                updated_at: T0,
            },
        )
        .unwrap();

        let state = InternalState {
            sessions,
            reader: Arc::new(Reader::new(reader_conn)),
            clock: Arc::new(TestClock::new(T0)),
            api_key: Some(Arc::from(API_KEY)),
            writer: None,
            last_touch: Default::default(),
            metrics: crate::telemetry::Metrics::new(),
            audit: None,
        };

        Harness {
            router: router(state),
            token: issued.token.expose_for_cookie().to_owned(),
            _writer: writer,
        }
    }

    fn request(api_key: Option<&str>, session_token: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/internal/token")
            .header("content-type", "application/json");
        if let Some(key) = api_key {
            builder = builder.header("authorization", format!("Bearer {key}"));
        }
        builder
            .body(Body::from(
                serde_json::json!({ "session_token": session_token }).to_string(),
            ))
            .unwrap()
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn both_halves_present_yields_the_access_token() {
        let h = harness();
        let response = h
            .router
            .clone()
            .oneshot(request(Some(API_KEY), &h.token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["access_token"], "upstream-access-token");
        assert_eq!(body["sub"], "alice");
    }

    /// INV-11's substance: the API key alone is not authority over anyone. A
    /// compromised backend key must not be a master key.
    #[tokio::test]
    async fn the_api_key_alone_yields_nothing() {
        let h = harness();
        let response = h
            .router
            .clone()
            .oneshot(request(Some(API_KEY), "not-a-real-session-token"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(response).await["error"], "session_not_active");
    }

    /// The other half, and the one that matters for XSS: a session token
    /// stolen from a browser cannot be exchanged for an upstream token,
    /// because the browser never holds the API key.
    #[tokio::test]
    async fn a_session_token_alone_yields_nothing() {
        let h = harness();
        let response = h
            .router
            .clone()
            .oneshot(request(None, &h.token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(response).await["error"], "missing_api_key");

        let wrong = h
            .router
            .clone()
            .oneshot(request(Some("wrong-key"), &h.token))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(wrong).await["error"], "bad_api_key");
    }

    /// A key of a different length must be refused without the comparison
    /// short-circuiting through the shared prefix.
    #[test]
    fn key_comparison_rejects_prefixes_and_length_mismatches() {
        assert!(key_matches(API_KEY, API_KEY));
        assert!(!key_matches("backend-key", API_KEY));
        assert!(!key_matches(&format!("{API_KEY}x"), API_KEY));
    }

    /// Unconfigured means off, not open. A deployment that never set a key
    /// must not have an unauthenticated token lane listening.
    #[tokio::test]
    async fn an_unconfigured_lane_is_closed_rather_than_open() {
        let conn = crate::store::open_in_memory().unwrap();
        let state = InternalState {
            sessions: Arc::new(SessionMap::new(SessionPolicy::default())),
            reader: Arc::new(Reader::new(conn)),
            clock: Arc::new(TestClock::new(T0)),
            api_key: None,
            writer: None,
            last_touch: Default::default(),
            metrics: crate::telemetry::Metrics::new(),
            audit: None,
        };
        let response = router(state)
            .oneshot(request(Some(API_KEY), "anything"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
