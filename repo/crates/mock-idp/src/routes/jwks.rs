//! `GET /jwks.json`

use axum::{extract::State, Json};
use serde_json::Value;

use super::SharedState;

pub async fn jwks(State(state): State<SharedState>) -> Json<Value> {
    state.record_jwks_call();
    Json(state.jwks_document())
}
