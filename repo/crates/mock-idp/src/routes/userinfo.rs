//! `GET /userinfo` — bearer-authenticated. Access tokens here are opaque,
//! server-tracked strings (not JWTs), so validity is a state lookup rather
//! than a signature check — which is also what lets `/__test__/expire`
//! invalidate one instantly without re-signing anything.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use super::SharedState;
use crate::state::now_unix;

pub async fn userinfo(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    state.record_userinfo_call();

    let Some(token) = bearer_token(&headers) else {
        return unauthorized("missing Bearer token");
    };
    let Some(record) = state.lookup_access_token(token) else {
        return unauthorized("unknown access token");
    };
    if record.expires_at <= now_unix() {
        return unauthorized("access token has expired");
    }
    let Some(user) = state.find_user(&record.subject) else {
        return unauthorized("subject no longer exists");
    };

    Json(json!({
        "sub": user.subject,
        "email": user.email,
        "name": user.name,
    }))
    .into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn unauthorized(description: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(json!({ "error": "invalid_token", "error_description": description })),
    )
        .into_response()
}
