//! The desktop sign-in handoff (RFC 8252 shape, broker ADR-0019).
//!
//! A desktop app has no cookie jar in common with the system browser, so a sign-in there has to be carried
//! back to the app another way:
//!
//! 1. The app picks a random `verifier`; the attempt id is `base64url(sha256(verifier))`. It opens the system
//!    browser at `/auth/login?provider=<id>&return_to=/auth/desktop?attempt=<id>`.
//! 2. `GET /auth/desktop?attempt=<id>`: the session that login just made is signed for the attempt.
//! 3. `POST /admin/desktop-handoff {attempt, verifier}` on the admin lane: the outcome, once.
//!
//! The attempt id travels through a browser, so it is not a credential: redeeming needs the admin key and the
//! verifier, which never leaves the app. A session already in that browser cannot be spent on an attempt: only
//! the login whose `return_to` named this attempt can bind it, which is what stops a link from signing the app in
//! with whoever happened to be signed in.
//!
//! The broker's restart loses everything here, which costs one retried sign-in. A token lives in this map for at
//! most [`ATTEMPT_TTL_SECS`]. A failed sign-in is held here too (code, detail, hint: the same words `/error` shows),
//! because the app is the one waiting for the answer.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::auth::{escape_html, failure_hint};
use super::error::ApiError;
use super::user_token::{self, Attempt as Issuance};
use super::{guards, AppState};
use crate::session::Resolution;
use crate::token::TokenHash;

pub const ATTEMPT_TTL_SECS: i64 = 300;
/// A flood of attempts evicts the oldest and costs those sign-ins one retry.
const ATTEMPTS_HELD: usize = 64;
/// `base64url(sha256(..))` without padding.
const ATTEMPT_LEN: usize = 43;
const PATH_PREFIX: &str = "/auth/desktop?attempt=";

/// The answer `POST /admin/desktop-handoff` gives for a finished attempt.
#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Outcome {
    Complete {
        access_token: String,
        expires_in: u64,
        tenant: String,
        roles: Vec<String>,
    },
    Failed {
        error: String,
        detail: String,
        hint: String,
    },
}

// By hand, so a token cannot reach a log through a stray `{:?}`.
impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Complete { .. } => f.write_str("Complete(redacted)"),
            Outcome::Failed { error, .. } => write!(f, "Failed({error})"),
        }
    }
}

#[derive(Default)]
struct Held {
    /// attempt -> the session its own login created, and when.
    logins: HashMap<String, (String, i64)>,
    /// attempt -> how it ended, and when.
    outcomes: HashMap<String, (Outcome, i64)>,
}

fn held() -> std::sync::MutexGuard<'static, Held> {
    static HELD: OnceLock<Mutex<Held>> = OnceLock::new();
    HELD.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

fn trim<V>(map: &mut HashMap<String, V>, now: i64, at: impl Fn(&V) -> i64) {
    map.retain(|_, v| at(v) + ATTEMPT_TTL_SECS > now);
    while map.len() >= ATTEMPTS_HELD {
        let Some(oldest) = map.iter().min_by_key(|(_, v)| at(v)).map(|(k, _)| k.clone()) else { return };
        map.remove(&oldest);
    }
}

fn is_attempt(value: &str) -> bool {
    value.len() == ATTEMPT_LEN && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The attempt a login's `return_to` names, if it is a desktop login.
pub(super) fn attempt_of(return_to: Option<&str>) -> Option<&str> {
    return_to?.strip_prefix(PATH_PREFIX).filter(|attempt| is_attempt(attempt))
}

/// A login for this attempt made this session. Only that session can bind it.
pub(super) fn note_login(attempt: &str, sid: &str, now: i64) {
    let mut held = held();
    trim(&mut held.logins, now, |v| v.1);
    held.logins.insert(attempt.to_owned(), (sid.to_owned(), now));
}

/// The sign-in for this attempt failed. The first ending stands.
pub(super) fn note_failure(attempt: &str, code: &str, detail: &str, now: i64) {
    let outcome = Outcome::Failed {
        error: code.to_owned(),
        detail: detail.chars().take(800).collect(),
        hint: failure_hint(code, detail).to_owned(),
    };
    finish(attempt, outcome, now);
}

fn finish(attempt: &str, outcome: Outcome, now: i64) -> bool {
    let mut held = held();
    trim(&mut held.outcomes, now, |v| v.1);
    if held.outcomes.contains_key(attempt) {
        return false;
    }
    held.outcomes.insert(attempt.to_owned(), (outcome, now));
    held.logins.remove(attempt);
    true
}

/// Does this verifier belong to this attempt? Both sides are hashes of secrets the caller has, on a lane
/// that already took the admin key, so an early-exit compare leaks nothing worth having.
pub(crate) fn verifier_matches(attempt: &str, verifier: &str) -> bool {
    is_attempt(attempt) && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == attempt
}

/// Take the attempt's outcome: `None` while it has none. One use: a second call finds nothing.
pub(crate) fn redeem(attempt: &str, now: i64) -> Option<Outcome> {
    let mut held = held();
    let (outcome, at) = held.outcomes.remove(attempt)?;
    (at + ATTEMPT_TTL_SECS > now).then_some(outcome)
}

#[derive(Deserialize)]
pub struct DesktopQuery {
    attempt: Option<String>,
}

fn page(status: StatusCode, title: &str, text: &str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title>\
         <body style=\"font:15px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem\">\
         <h1 style=\"font-size:1.4rem\">{title}</h1><p>{text}</p></body></html>",
        title = escape_html(title),
        text = escape_html(text),
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response()
}

fn code_of(err: &ApiError) -> String {
    serde_json::to_value(err.error)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "error".to_owned())
}

/// `GET /auth/desktop?attempt=<id>`: where a desktop login's `return_to` lands.
pub async fn desktop(State(state): State<AppState>, Query(query): Query<DesktopQuery>, headers: HeaderMap) -> Response {
    let Some(attempt) = query.attempt.as_deref().filter(|a| is_attempt(a)) else {
        return page(StatusCode::BAD_REQUEST, "Sign-in not recognised", "This link is not one the app made. Start again from the app.");
    };
    let refused = || {
        page(
            StatusCode::UNAUTHORIZED,
            "Not signed in",
            "This page only completes a sign-in the app started. Start again from the app.",
        )
    };
    let now = state.clock.now();
    let Some(cookie) = guards::cookie(&headers, state.config.session_cookie_name()) else {
        return refused();
    };
    let hash = TokenHash::of(cookie);
    if !matches!(state.sessions.resolve(&hash, now), Resolution::Active { .. }) {
        return refused();
    }
    let Some(meta) = state.sessions.meta_for(&hash) else {
        return refused();
    };
    // The session this attempt's own login created, and no other: see the module note.
    let fresh = held()
        .logins
        .get(attempt)
        .is_some_and(|(sid, at)| *sid == meta.sid && at + ATTEMPT_TTL_SECS > now.secs());
    if !fresh {
        return refused();
    }

    let Some(handle) = &state.issuer else {
        note_failure(attempt, "lane_disabled", "The broker's token issuer is not configured.", now.secs());
        return page(StatusCode::NOT_IMPLEMENTED, "Sign-in failed", "The broker's token issuer is not configured. Return to the app.");
    };
    // The handoff has no request body to choose an audience in, so an install with several has no answer here.
    let [audience] = handle.config.audiences.as_slice() else {
        note_failure(attempt, "lane_disabled", "The desktop handoff needs exactly one issuer audience.", now.secs());
        return page(StatusCode::NOT_IMPLEMENTED, "Sign-in failed", "The desktop handoff needs exactly one issuer audience. Return to the app.");
    };

    let mut issuance = Issuance::default();
    let tenant = handle.config.default_user_tenant.clone();
    match user_token::mint(&state, handle, &meta, audience.clone(), tenant, &mut issuance) {
        Ok(granted) => {
            state.metrics.record_token_issued(user_token::KIND, "issued");
            user_token::audit_issued(&state, &issuance, now);
            let outcome = Outcome::Complete {
                access_token: granted.access_token,
                expires_in: granted.expires_in,
                tenant: granted.tenant,
                roles: granted.roles,
            };
            if !finish(attempt, outcome, now.secs()) {
                return page(StatusCode::CONFLICT, "Sign-in not recognised", "This sign-in has already ended. Start again from the app.");
            }
            page(StatusCode::OK, "Signed in", "You are signed in. Return to the app; you can close this tab.")
        }
        Err(err) => {
            let code = code_of(&err);
            state.metrics.record_token_issued(user_token::KIND, &code);
            user_token::audit_refused(&state, &issuance, &code, now);
            note_failure(attempt, &code, &err.detail, now.secs());
            page(StatusCode::FORBIDDEN, "Sign-in failed", &format!("{} Return to the app for details.", failure_hint(&code, &err.detail)))
        }
    }
}
