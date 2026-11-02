//! `POST /admin/desktop-handoff`: the desktop app collects a sign-in (`http/desktop.rs`, ADR-0019).
//!
//! `{"attempt", "verifier"}` -> 200 `{"status": "pending"}` until the browser finishes; then, once,
//! `{"status": "complete", "access_token", "expires_in", "tenant", "roles"}` or
//! `{"status": "failed", "error", "detail", "hint"}`. A verifier that does not hash to the attempt is
//! 403 `bad_verifier`, and spends nothing. The token and verifier are never logged.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use super::identity::parse;
use super::{authorised, refuse, AdminState};
use crate::http::desktop;
use crate::http::guards::PeerAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    attempt: String,
    verifier: String,
}

pub(super) async fn redeem(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: Request = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !desktop::verifier_matches(&request.attempt, &request.verifier) {
        return refuse(StatusCode::FORBIDDEN, "bad_verifier", "that verifier does not belong to that attempt");
    }
    let answer = match desktop::redeem(&request.attempt, state.clock.now().secs()) {
        Some(outcome) => serde_json::to_value(&outcome).unwrap_or_else(|_| serde_json::json!({ "status": "failed", "error": "unavailable", "detail": "the outcome could not be read", "hint": "Start again." })),
        None => serde_json::json!({ "status": "pending" }),
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(answer)).into_response()
}
