//! The HTTP surface: router, shared state, and cookie construction.
//!
//! Deployment topology is single-origin path-mount (INV-10): the broker is
//! mounted at `/auth/*`, `/session/*` and `/proxy/*` on the SPA's own origin, so
//! no CORS surface exists at all.

use std::sync::Arc;

use axum::extract::FromRef;
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::clock::Clock;
use crate::session::{IssuedCookies, SessionMap, SessionMeta, SessionPolicy};

pub mod admin;
pub mod auth;
pub mod authz;
pub mod error;
pub mod events;
pub mod guards;
pub mod internal;
pub mod ops;
pub mod session;

#[cfg(test)]
mod tests;

/// Cookie names in hardened mode. `broker_meta` is deliberately *not*
/// `__Host-`-prefixed-and-HttpOnly: it must be readable by script (INV-9).
const SESSION_COOKIE: &str = "__Host-broker_session";
const META_COOKIE: &str = "broker_meta";
/// Dev mode drops the `__Host-` prefix, which mandates `Secure`. Only ever
/// reachable over loopback — see [`HttpConfig::new`].
const SESSION_COOKIE_DEV: &str = "broker_session";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpConfigError {
    #[error("base_url must be an absolute http(s) URL with a host, got '{0}'")]
    BadBaseUrl(String),
    #[error("base_url '{0}' is not https; plaintext is only allowed on loopback")]
    InsecureOffLoopback(String),
}

/// The subset of broker configuration the HTTP layer needs. Kept separate from
/// the full config so the router can be built in tests from two strings.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Scheme + host + port, used for the `Origin` fallback check and for
    /// building absolute login URLs.
    origin: String,
    /// False only on loopback. Drives both the `Secure` attribute and whether
    /// the `__Host-` prefix can be used.
    secure: bool,
    /// Where an expired client is sent to log in.
    login_path: String,
    /// Cookie `Max-Age`. Both cookies live for the full idle window so the
    /// browser keeps *sending* a stale generation — that token is the refresh
    /// credential, and freshness is a server-side judgement, never a cookie-jar
    /// one.
    max_age_secs: u64,
}

impl HttpConfig {
    pub fn new(base_url: &str, policy: &SessionPolicy) -> Result<HttpConfig, HttpConfigError> {
        let rest = base_url
            .strip_prefix("https://")
            .map(|r| (r, true))
            .or_else(|| base_url.strip_prefix("http://").map(|r| (r, false)));
        let Some((rest, secure)) = rest else {
            return Err(HttpConfigError::BadBaseUrl(base_url.to_owned()));
        };
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(HttpConfigError::BadBaseUrl(base_url.to_owned()));
        }

        let host = authority.split(':').next().unwrap_or_default();
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
        if !secure && !loopback {
            // Refusing this is the point: without it, a misconfigured base_url
            // would silently downgrade every cookie in production.
            return Err(HttpConfigError::InsecureOffLoopback(base_url.to_owned()));
        }

        Ok(HttpConfig {
            origin: format!("{}://{}", if secure { "https" } else { "http" }, authority),
            secure,
            login_path: "/auth/login".to_owned(),
            max_age_secs: policy.idle_ttl_secs,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn session_cookie_name(&self) -> &'static str {
        if self.secure {
            SESSION_COOKIE
        } else {
            SESSION_COOKIE_DEV
        }
    }

    pub fn meta_cookie_name(&self) -> &'static str {
        META_COOKIE
    }

    /// Absolute URL the client should navigate to in order to log in. Handed to
    /// the client in the error body so the SDK never builds one itself.
    pub fn login_url(&self, return_to: Option<&str>) -> String {
        match return_to {
            Some(path) => format!(
                "{}{}?return_to={}",
                self.origin,
                self.login_path,
                urlencode(path)
            ),
            None => format!("{}{}", self.origin, self.login_path),
        }
    }

    /// The interactive refresh URL — the one the SDK's `login()` navigates to.
    pub fn interactive_refresh_url(&self, return_to: Option<&str>) -> String {
        match return_to {
            Some(path) => format!(
                "{}/session/refresh?interactive=1&return_to={}",
                self.origin,
                urlencode(path)
            ),
            None => format!("{}/session/refresh?interactive=1", self.origin),
        }
    }

    fn attributes(&self, http_only: bool, max_age: i64) -> String {
        let mut attrs = format!("; Path=/; SameSite=Lax; Max-Age={max_age}");
        if self.secure {
            attrs.push_str("; Secure");
        }
        if http_only {
            attrs.push_str("; HttpOnly");
        }
        attrs
    }

    /// The `Set-Cookie` pair for a freshly issued or refreshed session: the
    /// secret, and the JS-readable hint that tells a dumb client when to act.
    pub fn issue_cookies(&self, issued: &IssuedCookies) -> [String; 2] {
        let max_age = self.max_age_secs as i64;
        [
            format!(
                "{}={}{}",
                self.session_cookie_name(),
                issued.token.expose_for_cookie(),
                self.attributes(true, max_age)
            ),
            format!(
                "{}={}{}",
                self.meta_cookie_name(),
                encode_meta(&issued.meta),
                self.attributes(false, max_age)
            ),
        ]
    }

    /// Expire both cookies. `Max-Age=0` plus an empty value, so a client that
    /// ignores one still ends up with nothing usable.
    pub fn clear_cookies(&self) -> [String; 2] {
        [
            format!(
                "{}={}",
                self.session_cookie_name(),
                self.attributes(true, 0)
            ),
            format!("{}={}", self.meta_cookie_name(), self.attributes(false, 0)),
        ]
    }
}

/// base64url of the meta JSON — encoded only so that a cookie value never has to
/// worry about quoting, not for secrecy. There is nothing secret in it.
pub fn encode_meta(meta: &SessionMeta) -> String {
    let json = serde_json::to_vec(meta).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json)
}

pub fn decode_meta(value: &str) -> Option<SessionMeta> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Minimal percent-encoding for a path we have already validated as a
/// same-origin absolute path (INV-4), so only delimiters need escaping.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<SessionMap>,
    pub clock: Arc<dyn Clock>,
    pub config: Arc<HttpConfig>,
    /// Where `/auth/callback` puts the upstream grant it just obtained.
    ///
    /// `None` in the state-machine and cookie tests, which exercise session
    /// behaviour and have no store behind them. Production always supplies
    /// one — without it a login would mint a session with no upstream grant.
    pub custody: Option<crate::custody::CustodySink>,
    /// The audit record. `None` in the state-machine and cookie tests, which
    /// have no store behind them.
    pub audit: Option<crate::audit::AuditSink>,
    pub metrics: Arc<crate::telemetry::Metrics>,
}

impl FromRef<AppState> for Arc<HttpConfig> {
    fn from_ref(state: &AppState) -> Arc<HttpConfig> {
        state.config.clone()
    }
}

/// The session lane, plus `/auth/*` (M2). `/proxy/*` (M5) mounts alongside
/// later.
///
/// The two `/auth/*` handlers need an `Arc<OidcClient>` that this function's
/// signature has no room for (it is called throughout the existing test
/// suite with only an `AppState`) — so it is supplied as a request
/// extension, layered on by whoever finishes building the app (see
/// `http/auth.rs`'s module docs), not as part of `AppState`. Routes that
/// never touch `/auth/*` are unaffected either way.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/session", get(session::get_session))
        .route("/session/events", get(events::stream))
        .route(
            "/session/refresh",
            post(session::post_refresh).get(session::get_refresh),
        )
        .route("/logout", post(session::post_logout))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .with_state(state)
}
