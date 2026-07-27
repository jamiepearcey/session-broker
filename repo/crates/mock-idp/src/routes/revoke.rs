//! `POST /revoke` — RFC 7009. Idempotent: revoking an unknown or
//! already-revoked token still returns 200, per the RFC's guidance not to
//! let this endpoint leak whether a token value exists.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use serde::Deserialize;

use super::SharedState;

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: Option<String>,
    // Accepted for RFC 7009 shape-compatibility; this fixture revokes by
    // token value alone and doesn't need the hint or the caller's identity.
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    #[allow(dead_code)]
    pub client_id: Option<String>,
}

pub async fn revoke(State(state): State<SharedState>, Form(form): Form<RevokeForm>) -> Response {
    state.record_revoke_call();
    if let Some(token) = form.token.as_deref() {
        state.revoke_token_value(token);
    }
    StatusCode::OK.into_response()
}
