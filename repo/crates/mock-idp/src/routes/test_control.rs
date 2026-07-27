//! `/__test__/*` — the reason this crate exists. Deliberately namespaced
//! away from the OAuth-shaped routes so it can never be mistaken for part
//! of the protocol surface; `spawn_mock_idp` logs a loud warning at startup
//! that this control API — and the whole server — must never be deployed.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use super::SharedState;
use crate::state::{now_unix, FailNext, RuntimeConfigPatch};

/// `POST /__test__/config` — partial update of TTLs, rotation policy, and
/// injected `/token` latency. Fields left out keep their current value.
/// Returns the resulting full config.
pub async fn set_config(
    State(state): State<SharedState>,
    Json(patch): Json<RuntimeConfigPatch>,
) -> impl IntoResponse {
    Json(state.patch_runtime_config(patch))
}

#[derive(Debug, Deserialize)]
pub struct SubjectRequest {
    pub subject: String,
}

/// `POST /__test__/expire` — force every live token belonging to `subject`
/// into the past, immediately.
pub async fn expire(
    State(state): State<SharedState>,
    Json(body): Json<SubjectRequest>,
) -> impl IntoResponse {
    let expired = state.force_expire_subject(&body.subject, now_unix());
    Json(json!({ "expired": expired }))
}

/// `POST /__test__/revoke-refresh` — revoke `subject`'s refresh token(s),
/// so the next refresh grant against them fails `invalid_grant`.
pub async fn revoke_refresh(
    State(state): State<SharedState>,
    Json(body): Json<SubjectRequest>,
) -> impl IntoResponse {
    let revoked = state.revoke_refresh_for_subject(&body.subject);
    Json(json!({ "revoked": revoked }))
}

#[derive(Debug, Deserialize)]
pub struct FailNextRequest {
    #[serde(default = "default_fail_count")]
    pub count: u32,
    #[serde(default = "default_fail_status")]
    pub status: u16,
    #[serde(default = "default_fail_error")]
    pub error: String,
    pub error_description: Option<String>,
}

fn default_fail_count() -> u32 {
    1
}

fn default_fail_status() -> u16 {
    503
}

fn default_fail_error() -> String {
    "temporarily_unavailable".to_owned()
}

/// `POST /__test__/fail-next` — make the next `count` calls to `/token`
/// fail with the given status/error, for testing the broker's retry and
/// backoff behaviour without a real flaky upstream.
pub async fn fail_next(
    State(state): State<SharedState>,
    Json(body): Json<FailNextRequest>,
) -> impl IntoResponse {
    state.queue_fail_next(FailNext {
        remaining: body.count.max(1),
        status: body.status,
        error: body.error,
        error_description: body.error_description,
    });
    StatusCode::NO_CONTENT
}

/// `GET /__test__/state` — full dump of issued tokens, subjects, and call
/// counters (including the `/token`-call counter, broken down by grant
/// type, that a broker's tests assert on to prove the fast refresh path
/// never reaches this server).
pub async fn dump_state(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.snapshot())
}
