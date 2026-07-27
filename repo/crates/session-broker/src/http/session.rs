//! `/session`, `/session/refresh` and `/logout`.
//!
//! The refresh handler is the hot path and does no I/O at all (INV-8): it
//! resolves a hash in memory, coalesces or rotates, and writes two cookies. The
//! `X-Broker-Handler-Us` header reports the time spent inside the handler so the
//! demo can show the server-side cost separately from network round-trip —
//! measured, never asserted.

use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::error::{ApiError, ErrorCode};
use super::guards::{self, AllowDirectNavigation};
use super::{AppState, HttpConfig};
use crate::session::{ExpiredReason, IssuedCookies, RefreshDenied, Resolution};
use crate::token::TokenHash;

#[derive(Debug, Default, Deserialize)]
pub struct RefreshQuery {
    /// Present and truthy: the caller wants to be *sent* to the IdP rather than
    /// told it needs to log in. Only meaningful when the session is beyond
    /// saving; an active or merely stale session refreshes locally either way.
    #[serde(default)]
    interactive: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
}

impl RefreshQuery {
    fn interactive(&self) -> bool {
        matches!(self.interactive.as_deref(), Some("1" | "true" | "yes"))
    }
}

/// `GET /session` — read-only introspection. No rotation, no side effects.
pub async fn get_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let now = state.clock.now();
    let Some(hash) = presented(&headers, &state.config) else {
        return unauthenticated(&state.config, None).into_response();
    };

    match state.sessions.resolve(&hash, now) {
        Resolution::Active { .. } | Resolution::StaleRefreshable { .. } => {
            match state.sessions.meta_for(&hash) {
                Some(meta) => json_no_store(StatusCode::OK, &meta),
                None => unauthenticated(&state.config, None).into_response(),
            }
        }
        other => denial(other, &state.config, None).into_response(),
    }
}

/// `POST /session/refresh` — the hot path.
pub async fn post_refresh(
    State(state): State<AppState>,
    Query(query): Query<RefreshQuery>,
    headers: HeaderMap,
) -> Response {
    let started = Instant::now();

    if let Err(err) =
        guards::require_same_origin(&headers, state.config.origin(), AllowDirectNavigation::No)
    {
        return err.into_response();
    }

    let return_to = guards::safe_return_to(query.return_to.as_deref());
    match refresh(&state, &headers, return_to.as_deref()) {
        Ok(issued) => issued_response(&state.config, &issued, started),
        // The POST form never redirects: a fetch cannot follow a cross-origin
        // redirect chain into a login page, so the client is handed the URL and
        // decides for itself.
        Err(err) => err.into_response(),
    }
}

/// `GET /session/refresh?interactive=1` — the navigation form. This is what the
/// SDK's `login()` points the browser at.
pub async fn get_refresh(
    State(state): State<AppState>,
    Query(query): Query<RefreshQuery>,
    headers: HeaderMap,
) -> Response {
    let started = Instant::now();

    if !guards::is_navigation(&headers) {
        return ApiError::new(
            ErrorCode::BadRequest,
            "the GET form of refresh is for top-level navigation; use POST",
        )
        .into_response();
    }
    // A top-level navigation legitimately arrives as `sec-fetch-site: none`
    // (address bar, bookmark) as well as `same-origin`.
    if let Err(err) =
        guards::require_same_origin(&headers, state.config.origin(), AllowDirectNavigation::Yes)
    {
        return err.into_response();
    }

    let return_to = guards::safe_return_to(query.return_to.as_deref());
    let destination = return_to.clone().unwrap_or_else(|| "/".to_owned());

    match refresh(&state, &headers, return_to.as_deref()) {
        // Active or stale: refreshed locally, straight back to the app. The
        // `interactive` flag is ignored here — there is nothing to log into.
        Ok(issued) => {
            let mut response = issued_response(&state.config, &issued, started);
            *response.status_mut() = StatusCode::SEE_OTHER;
            response.headers_mut().insert(
                header::LOCATION,
                destination
                    .parse()
                    .unwrap_or(header::HeaderValue::from_static("/")),
            );
            response
        }
        Err(_) if query.interactive() => {
            // Beyond local recovery and the caller asked to be pushed through
            // the IdP. Clear the dead cookies on the way out so a failed login
            // does not leave a corpse behind.
            let login = state.config.login_url(return_to.as_deref());
            let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, login)]).into_response();
            for cookie in state.config.clear_cookies() {
                if let Ok(value) = cookie.parse() {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Err(err) => err.into_response(),
    }
}

/// `POST /logout` — INV-7. Idempotent: always 200, even for a session that was
/// already dead, because a client retrying logout must not see an error.
pub async fn post_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) =
        guards::require_same_origin(&headers, state.config.origin(), AllowDirectNavigation::No)
    {
        return err.into_response();
    }

    let now = state.clock.now();
    if let Some(hash) = presented(&headers, &state.config) {
        // Resolve to a sid without caring whether it is still valid: logging out
        // an already-expired session must still clear it.
        if let Some(sid) = state.sessions.sid_for_hash(&hash) {
            let sub = state.sessions.meta_for(&hash).map(|m| m.sub);
            let killed = state.sessions.tombstone_session(&sid, now);
            // Recorded only when this call is what ended it. Logout is
            // idempotent, so a client retrying would otherwise write a row per
            // retry for a session that died once.
            if killed {
                if let Some(sink) = &state.audit {
                    let mut event = crate::audit::Event::new(
                        crate::audit::action::SESSION_LOGGED_OUT,
                        crate::audit::Outcome::Success,
                        crate::audit::ActorKind::User,
                        now,
                    )
                    .sid(sid.0.clone());
                    if let Some(sub) = sub {
                        event = event.subject(sub);
                    }
                    sink.record(event);
                }
            }
        }
    }

    let mut response = json_no_store(StatusCode::OK, &serde_json::json!({ "logged_out": true }));
    for cookie in state.config.clear_cookies() {
        if let Ok(value) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn refresh(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
) -> Result<IssuedCookies, ApiError> {
    let now = state.clock.now();
    let Some(hash) = presented(headers, &state.config) else {
        return Err(unauthenticated(&state.config, return_to));
    };
    // Read BEFORE the refresh, because refreshing changes what the token
    // resolves to. This is the INV-6a check: a generation still inside its
    // grace window is legitimate — that is the product — but using one instead
    // of the newest means two actors hold cookies for one session, which is
    // exactly the signal the invariant asks for.
    let before = state.sessions.resolve(&hash, now);
    if let Resolution::Active {
        sid,
        gen_no,
        newest: false,
    } = &before
    {
        state.metrics.record_anomaly("superseded_generation");
        if let Some(sink) = &state.audit {
            sink.record(
                crate::audit::Event::new(
                    crate::audit::action::SESSION_ANOMALY,
                    crate::audit::Outcome::Success,
                    crate::audit::ActorKind::User,
                    now,
                )
                .sid(sid.0.clone())
                .reason("superseded_generation")
                .detail(serde_json::json!({ "gen_no": gen_no })),
            );
        }
    }
    if let Resolution::Retired { sid, gen_no } = &before {
        // Past the grace window entirely. Denied below; recorded here because a
        // cookie surfacing after its generation was reaped is the shape a
        // replayed or exfiltrated cookie has. Signal, not revocation (INV-6a).
        state.metrics.record_anomaly("retired_generation");
        if let Some(sink) = &state.audit {
            sink.record(
                crate::audit::Event::new(
                    crate::audit::action::SESSION_ANOMALY,
                    crate::audit::Outcome::Failure,
                    crate::audit::ActorKind::User,
                    now,
                )
                .sid(sid.0.clone())
                .reason("retired_generation")
                .detail(serde_json::json!({ "gen_no": gen_no })),
            );
        }
    }

    let outcome = state
        .sessions
        .refresh(&hash, now)
        .map_err(|denied| map_denial(denied, &state.config, return_to));

    // Counters only on the hot path (ADR-0015). `coalesced` is the
    // non-invalidating-rotation guarantee doing its job, and worth watching
    // separately from a real rotation.
    state.metrics.record_refresh(match (&before, &outcome) {
        (_, Err(_)) => "refused",
        (Resolution::StaleRefreshable { .. }, Ok(_)) => "rotated",
        (_, Ok(_)) => "coalesced",
    });

    outcome
}

fn presented(headers: &HeaderMap, config: &HttpConfig) -> Option<TokenHash> {
    guards::cookie(headers, config.session_cookie_name()).map(TokenHash::of)
}

fn unauthenticated(config: &HttpConfig, return_to: Option<&str>) -> ApiError {
    ApiError::new(ErrorCode::InvalidSession, "no session cookie presented")
        .with_login_url(config.login_url(return_to))
}

fn map_denial(denied: RefreshDenied, config: &HttpConfig, return_to: Option<&str>) -> ApiError {
    match denied {
        RefreshDenied::Unknown => unauthenticated(config, return_to),
        RefreshDenied::Retired { gen_no, .. } => ApiError::new(
            ErrorCode::InvalidSession,
            format!("generation {gen_no} is past its grace window"),
        )
        .with_login_url(config.login_url(return_to)),
        RefreshDenied::Expired { reason, .. } => expired_error(reason, config),
    }
}

fn denial(resolution: Resolution, config: &HttpConfig, return_to: Option<&str>) -> ApiError {
    match resolution {
        Resolution::HardExpired { reason, .. } => expired_error(reason, config),
        Resolution::Retired { gen_no, .. } => ApiError::new(
            ErrorCode::InvalidSession,
            format!("generation {gen_no} is past its grace window"),
        )
        .with_login_url(config.login_url(return_to)),
        _ => unauthenticated(config, return_to),
    }
}

fn expired_error(reason: ExpiredReason, config: &HttpConfig) -> ApiError {
    let code = match reason {
        ExpiredReason::UpstreamRevoked => ErrorCode::UpstreamRevoked,
        _ => ErrorCode::SessionExpired,
    };
    ApiError::new(code, format!("session expired ({reason:?})"))
        .with_login_url(config.login_url(None))
}

fn issued_response(config: &HttpConfig, issued: &IssuedCookies, started: Instant) -> Response {
    let mut response = json_no_store(StatusCode::OK, &issued.meta);
    for cookie in config.issue_cookies(issued) {
        if let Ok(value) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    if let Ok(value) = started.elapsed().as_micros().to_string().parse() {
        response.headers_mut().insert("x-broker-handler-us", value);
    }
    response
}

fn json_no_store<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let encoded = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_owned());
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        encoded,
    )
        .into_response()
}
