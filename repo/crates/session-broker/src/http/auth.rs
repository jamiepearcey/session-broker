//! `GET /auth/login` and `GET /auth/callback` — the OAuth2/OIDC
//! authorization-code entry path (M2, §4 of the implementation strategy).
//!
//! ## Wiring: why an `Extension`, not `State`
//!
//! `http::router(state)`'s signature is fixed — dozens of existing tests
//! call it with nothing but an `AppState`, and `AppState` itself carries no
//! OIDC client (nor may it gain one for this milestone). Rather than
//! changing either, the two handlers below take their `Arc<OidcClient>` as
//! an axum request [`Extension`] instead of a second `State`: extensions are
//! populated by a `tower::Layer`, which can be applied to the already-built
//! router from *outside* `http::router`, so none of the existing state
//! plumbing has to move. Whoever assembles the full app — production
//! wiring, or this module's own tests — does:
//!
//! ```ignore
//! let app = session_broker::http::router(state)
//!     .layer(axum::extract::Extension(Arc::new(oidc_client)));
//! ```
//!
//! Every other route ignores the extension; only these two extract it, so
//! routes that never see `/auth/*` traffic behave identically whether or not
//! the layer is present.

use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::error::{ApiError, ErrorCode};
use super::guards;
use super::{AppState, HttpConfig};
use crate::clock::Timestamp;
use crate::oauth::{random_id, OauthError, OidcClient, UpstreamTokens, TXN_TTL_SECS};
use crate::session::{CustodyId, Sid};

#[derive(Debug, Default, Deserialize)]
pub struct LoginQuery {
    return_to: Option<String>,
}

/// `GET /auth/login?return_to=/path` — validates `return_to` (INV-4, via the
/// existing `guards::safe_return_to`), starts a login transaction (INV-3),
/// cookies its opaque id, and sends the browser to the IdP.
pub async fn login(
    State(state): State<AppState>,
    Extension(oidc): Extension<Arc<OidcClient>>,
    Query(query): Query<LoginQuery>,
) -> Response {
    // Absent is fine (no redirect target requested); present-but-unsafe is
    // rejected outright rather than silently downgraded, per the documented
    // `/auth/login` contract (`400 bad_request`) — unlike the interactive
    // refresh navigation, which falls back to `/` instead, this endpoint
    // hasn't started a transaction yet, so there is nothing to protect by
    // continuing.
    let return_to = match query.return_to.as_deref() {
        None => None,
        Some(raw) => match guards::safe_return_to(Some(raw)) {
            Some(safe) => Some(safe),
            None => {
                return ApiError::new(
                    ErrorCode::BadRequest,
                    "return_to must be a same-origin absolute path",
                )
                .into_response()
            }
        },
    };

    let now = state.clock.now();
    let (authorize_url, txn) = oidc.begin_login(return_to, now);

    let mut response = redirect(&authorize_url);
    append_cookie(
        &mut response,
        txn_cookie(&state.config, txn.cookie_value(), TXN_TTL_SECS as i64),
    );
    response
}

#[derive(Debug, Default, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/callback?code=&state=` (and the `?error=` form). Any failure —
/// missing txn cookie, `state` mismatch, expired txn, failed exchange, bad
/// `id_token` — deletes the txn, creates no session, and lands on the
/// configured error page with `?error=oauth_error`. Success creates the
/// session via the existing `SessionMap::create`, issues its cookies via the
/// existing `HttpConfig::issue_cookies`, and redirects to the txn's stored
/// `return_to`.
pub async fn callback(
    State(state): State<AppState>,
    Extension(oidc): Extension<Arc<OidcClient>>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let now = state.clock.now();
    let txn_id = guards::cookie(&headers, txn_cookie_name(&state.config)).map(str::to_owned);

    let mut response = match txn_id.as_deref() {
        // INV-3a: no txn cookie at all. Nothing was ever created for this
        // request, so there is nothing to discard — straight to the error
        // page, no session.
        None => error_redirect(&state.config),
        Some(id) => match resolve(&oidc, id, &query, now).await {
            Ok((tokens, return_to)) => success_response(&state, tokens, return_to, now),
            Err(error) => {
                tracing::warn!(%error, "oauth callback failed");
                error_redirect(&state.config)
            }
        },
    };

    // The txn cookie's job ends here regardless of outcome: expire it so a
    // retried navigation to this URL is unambiguously a fresh, cookie-less
    // attempt rather than a reuse of this one.
    append_cookie(&mut response, expire_txn_cookie(&state.config));
    response
}

/// The one "touch" of the presented txn (INV-3: deletion happens on first
/// touch, success or failure alike) — every early-return path here still
/// consumes the txn before giving up.
async fn resolve(
    oidc: &OidcClient,
    txn_id: &str,
    query: &CallbackQuery,
    now: Timestamp,
) -> Result<(UpstreamTokens, Option<String>), OauthError> {
    if let Some(error) = &query.error {
        oidc.discard_txn(txn_id);
        return Err(OauthError::ProviderError(error.clone()));
    }
    let (Some(code), Some(state_param)) = (query.code.as_deref(), query.state.as_deref()) else {
        oidc.discard_txn(txn_id);
        return Err(OauthError::ProviderError(
            "callback is missing code or state".to_owned(),
        ));
    };
    oidc.complete_login(txn_id, state_param, code, now).await
}

fn success_response(
    state: &AppState,
    tokens: UpstreamTokens,
    return_to: Option<String>,
    now: Timestamp,
) -> Response {
    let sid = Sid(random_id());
    let custody = CustodyId(random_id());

    // Custody FIRST, write-through, and a failure here fails the login.
    //
    // Two reasons the order is not negotiable. `session.custody_id` is a
    // foreign key onto `custody`, so a session written first would fail its
    // own batch. And a session created without a durable grant behind it is a
    // session whose every upstream call will fail for its entire life — the
    // user would appear logged in and be unable to do anything, which is worse
    // than being told the login failed and retrying.
    if let Some(sink) = &state.custody {
        let grant = crate::custody::NewGrant {
            sub: tokens.sub.clone(),
            // An IdP that returned no refresh token means custody cannot be
            // renewed; the access token still works until it expires, and the
            // keepalive worker will mark the custody dead when it cannot
            // refresh. Recording it empty is honest about that.
            refresh_token: tokens.refresh_token.clone().unwrap_or_default(),
            access_token: tokens.access_token.clone(),
            access_exp: tokens.expires_at,
            scope: tokens.scope.clone(),
        };
        if let Err(e) = sink.take_custody(&custody, &grant, now) {
            tracing::error!(error = %e, "could not take custody of the upstream grant; refusing the login");
            return error_redirect(&state.config);
        }
    }

    let issued = state
        .sessions
        .create(sid.clone(), custody.clone(), tokens.sub.clone(), now);

    if let Some(sink) = &state.audit {
        sink.record(
            crate::audit::Event::new(
                crate::audit::action::SESSION_CREATED,
                crate::audit::Outcome::Success,
                crate::audit::ActorKind::User,
                now,
            )
            .subject(tokens.sub.clone())
            .sid(sid.0.clone())
            .custody_id(custody.0.clone()),
        );
    }

    // INV-4, belt and suspenders: re-validate before trusting a value that,
    // structurally, can only ever have come from a prior, already-validated
    // `/auth/login` call — the IdP itself never sees or influences it.
    let destination =
        guards::safe_return_to(return_to.as_deref()).unwrap_or_else(|| "/".to_owned());

    let mut response = redirect(&destination);
    for cookie in state.config.issue_cookies(&issued) {
        append_cookie(&mut response, cookie);
    }
    response
}

/// `/auth/*`'s failure destination. `HttpConfig` carries no configurable
/// error page today (only a hardcoded `login_path`, built the same way) and
/// must not gain one for this milestone (see this module's wiring note and
/// `http/mod.rs`'s docs), so `/error` — the same default
/// `BrokerConfig::error_page_path` already uses — is hardcoded here too.
fn error_redirect(config: &HttpConfig) -> Response {
    redirect(&format!("{}/error?error=oauth_error", config.origin()))
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        location.parse().unwrap_or(HeaderValue::from_static("/")),
    );
    response
}

fn append_cookie(response: &mut Response, cookie: String) {
    if let Ok(value) = cookie.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// `__Host-broker_txn` in hardened mode, `broker_txn` over loopback —
/// mirrors exactly the derivation `HttpConfig::session_cookie_name` makes.
/// `HttpConfig` exposes no `secure` accessor for this module to read
/// directly, so this infers the same boolean from the one public signal
/// that already carries it: whether the session cookie name carries the
/// `__Host-` prefix. Getting this wrong would silently break dev (loopback,
/// non-HTTPS) logins, since `Secure` cookies are dropped there.
fn txn_cookie_name(config: &HttpConfig) -> &'static str {
    if config.session_cookie_name().starts_with("__Host-") {
        "__Host-broker_txn"
    } else {
        "broker_txn"
    }
}

/// Built to match `HttpConfig`'s own attribute ordering
/// (`Path=/; SameSite=Lax; Max-Age=...[; Secure]; HttpOnly`), so the txn
/// cookie is indistinguishable in shape from the session/meta cookies it
/// sits alongside — see `http/mod.rs`'s `HttpConfig::attributes`.
fn txn_cookie(config: &HttpConfig, value: &str, max_age: i64) -> String {
    let name = txn_cookie_name(config);
    let mut attrs = format!("; Path=/; SameSite=Lax; Max-Age={max_age}");
    if name.starts_with("__Host-") {
        attrs.push_str("; Secure");
    }
    attrs.push_str("; HttpOnly");
    format!("{name}={value}{attrs}")
}

fn expire_txn_cookie(config: &HttpConfig) -> String {
    txn_cookie(config, "", 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use mock_idp::{spawn_mock_idp, MockIdpConfig, MockIdpHandle};
    use tower::ServiceExt as _;

    use super::*;
    use crate::clock::TestClock;
    use crate::session::{SessionMap, SessionPolicy};

    const T0: Timestamp = Timestamp(1_700_000_000);
    const ORIGIN: &str = "https://app.example.com";
    const CLIENT_ID: &str = "session-broker-dev";
    const CLIENT_SECRET: &str = "dev-secret";
    const REDIRECT_URI: &str = "http://localhost:8080/auth/callback";

    struct Harness {
        router: Router,
        sessions: Arc<SessionMap>,
        idp: MockIdpHandle,
    }

    impl Harness {
        async fn new() -> Harness {
            let idp = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
            let oidc = OidcClient::discover_for_tests(
                idp.base_url(),
                CLIENT_ID,
                CLIENT_SECRET,
                REDIRECT_URI,
                &["openid", "offline_access"],
            )
            .await
            .expect("discovery against the spawned mock IdP must succeed");

            let clock = TestClock::new(T0);
            let sessions = Arc::new(SessionMap::new(SessionPolicy::default()));
            let config = Arc::new(HttpConfig::new(ORIGIN, &SessionPolicy::default()).unwrap());
            let state = AppState {
                sessions: sessions.clone(),
                clock: Arc::new(clock),
                config,
                custody: None,
                audit: None,
                metrics: crate::telemetry::Metrics::new(),
            };
            let router = crate::http::router(state).layer(Extension(Arc::new(oidc)));

            Harness {
                router,
                sessions,
                idp,
            }
        }

        async fn send(&self, request: Request<Body>) -> Response {
            self.router.clone().oneshot(request).await.unwrap()
        }

        async fn shutdown(self) {
            self.idp.shutdown().await;
        }
    }

    fn get(uri: String) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn get_with_cookie(uri: String, cookie: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("cookie", cookie.to_owned())
            .body(Body::empty())
            .unwrap()
    }

    fn location(response: &Response) -> String {
        response
            .headers()
            .get(header::LOCATION)
            .expect("a Location header")
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn set_cookie_named(response: &Response, name: &str) -> Option<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }

    fn query_param(url: &str, name: &str) -> Option<String> {
        openidconnect::url::Url::parse(url)
            .ok()?
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// Drive the authorize URL a real `/auth/login` produced against the
    /// spawned mock IdP over the network, and pull `code`/`state` out of the
    /// `Location` it answers with. Nothing needs to listen on `REDIRECT_URI`
    /// — the code and state are read straight off the header, the same
    /// technique `mock-idp`'s own test suite uses.
    async fn authorize(authorize_url: &str) -> (String, String) {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client.get(authorize_url).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        (
            query_param(&location, "code").expect("mock IdP redirect carries a code"),
            query_param(&location, "state").expect("mock IdP redirect carries state"),
        )
    }

    // --- happy path --------------------------------------------------------

    #[tokio::test]
    async fn happy_path_login_then_callback_yields_a_session_the_refresh_endpoint_accepts() {
        let h = Harness::new().await;

        let login_response = h
            .send(get("/auth/login?return_to=/dashboard".to_owned()))
            .await;
        assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
        let authorize_url = location(&login_response);
        assert!(authorize_url.starts_with(h.idp.base_url()));
        let txn_cookie =
            set_cookie_named(&login_response, "__Host-broker_txn").expect("txn cookie set");

        let (code, state_param) = authorize(&authorize_url).await;

        let callback_response = h
            .send(get_with_cookie(
                format!("/auth/callback?code={code}&state={state_param}"),
                &txn_cookie,
            ))
            .await;
        assert_eq!(callback_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&callback_response), "/dashboard");
        assert!(
            set_cookie_named(&callback_response, "__Host-broker_txn")
                .unwrap()
                .contains("__Host-broker_txn="),
            "the txn cookie must be expired on the way out"
        );
        let session_cookie = set_cookie_named(&callback_response, "__Host-broker_session")
            .expect("session cookie set");
        assert_eq!(h.sessions.len(), 1);

        let refresh_response = h
            .send(
                Request::builder()
                    .method("POST")
                    .uri("/session/refresh")
                    .header("sec-fetch-site", "same-origin")
                    .header("cookie", session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            refresh_response.status(),
            StatusCode::OK,
            "the existing /session/refresh endpoint must accept the minted session"
        );

        h.shutdown().await;
    }

    // --- INV-3a: no txn cookie --------------------------------------------

    #[tokio::test]
    async fn callback_without_a_txn_cookie_is_rejected_and_creates_no_session() {
        let h = Harness::new().await;

        let response = h
            .send(get("/auth/callback?code=whatever&state=whatever".to_owned()))
            .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let dest = location(&response);
        assert!(dest.contains("/error"));
        assert!(dest.contains("error=oauth_error"));
        assert_eq!(h.sessions.len(), 0, "no session may be created");

        h.shutdown().await;
    }

    // --- INV-3c, at the HTTP layer: replaying a used callback -----------------

    #[tokio::test]
    async fn replaying_a_successful_callback_is_rejected_the_second_time() {
        let h = Harness::new().await;

        let login_response = h.send(get("/auth/login".to_owned())).await;
        let authorize_url = location(&login_response);
        let txn_cookie =
            set_cookie_named(&login_response, "__Host-broker_txn").expect("txn cookie set");
        let (code, state_param) = authorize(&authorize_url).await;
        let callback_uri = format!("/auth/callback?code={code}&state={state_param}");

        let first = h
            .send(get_with_cookie(callback_uri.clone(), &txn_cookie))
            .await;
        assert_eq!(first.status(), StatusCode::SEE_OTHER);
        assert_eq!(h.sessions.len(), 1);

        // The txn cookie itself was expired by the first response, but an
        // attacker replaying the request need only resend the ORIGINAL
        // cookie value, which is exactly what this does.
        let second = h.send(get_with_cookie(callback_uri, &txn_cookie)).await;
        assert!(location(&second).contains("/error"));
        assert_eq!(
            h.sessions.len(),
            1,
            "the replay must not mint a second session"
        );

        h.shutdown().await;
    }

    // --- the `?error=` form -------------------------------------------------

    #[tokio::test]
    async fn an_idp_reported_error_is_redirected_without_a_session() {
        let h = Harness::new().await;

        let login_response = h.send(get("/auth/login".to_owned())).await;
        let txn_cookie =
            set_cookie_named(&login_response, "__Host-broker_txn").expect("txn cookie set");

        let response = h
            .send(get_with_cookie(
                "/auth/callback?error=access_denied".to_owned(),
                &txn_cookie,
            ))
            .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(location(&response).contains("error=oauth_error"));
        assert_eq!(h.sessions.len(), 0);

        h.shutdown().await;
    }

    // --- INV-4: no open redirect -------------------------------------------

    #[tokio::test]
    async fn a_hostile_return_to_never_reaches_the_login_redirect() {
        let h = Harness::new().await;

        for bad in [
            "//evil.example.com",
            "/\\evil.example.com",
            "https://evil.example.com",
        ] {
            let uri = format!("/auth/login?return_to={}", bad.replace('\\', "%5C"));
            let response = h.send(get(uri)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "return_to {bad:?} must be rejected, not redirected"
            );
            assert!(
                response.headers().get(header::LOCATION).is_none(),
                "a rejected return_to must never produce a Location header"
            );
        }

        h.shutdown().await;
    }

    #[tokio::test]
    async fn an_absent_return_to_is_accepted_and_falls_back_to_root_on_success() {
        let h = Harness::new().await;

        let login_response = h.send(get("/auth/login".to_owned())).await;
        assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
        let authorize_url = location(&login_response);
        let txn_cookie =
            set_cookie_named(&login_response, "__Host-broker_txn").expect("txn cookie set");
        let (code, state_param) = authorize(&authorize_url).await;

        let callback_response = h
            .send(get_with_cookie(
                format!("/auth/callback?code={code}&state={state_param}"),
                &txn_cookie,
            ))
            .await;
        assert_eq!(location(&callback_response), "/");

        h.shutdown().await;
    }

    // --- cookie hardening (INV-1-shaped, for the txn cookie) ------------------

    #[tokio::test]
    async fn the_login_txn_cookie_is_hardened() {
        let h = Harness::new().await;
        let response = h.send(get("/auth/login".to_owned())).await;

        let cookies: Vec<String> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let txn = cookies
            .iter()
            .find(|c| c.starts_with("__Host-broker_txn="))
            .expect("txn cookie");
        assert!(txn.contains("; Secure"));
        assert!(txn.contains("; HttpOnly"));
        assert!(txn.contains("; SameSite=Lax"));
        assert!(txn.contains("; Path=/"));
        assert!(txn.contains("; Max-Age=600"));
        assert!(!txn.contains("Domain="), "__Host- forbids Domain");

        h.shutdown().await;
    }

    #[test]
    fn txn_cookie_name_drops_the_host_prefix_over_loopback() {
        let policy = SessionPolicy::default();
        let hardened = HttpConfig::new("https://app.example.com", &policy).unwrap();
        assert_eq!(txn_cookie_name(&hardened), "__Host-broker_txn");

        let dev = HttpConfig::new("http://localhost:5173", &policy).unwrap();
        assert_eq!(txn_cookie_name(&dev), "broker_txn");
        assert!(!txn_cookie(&dev, "x", 600).contains("Secure"));
    }
}
