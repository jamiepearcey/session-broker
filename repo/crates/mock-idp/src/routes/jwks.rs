//! `GET /jwks.json`

use axum::{extract::State, Json};
use serde_json::Value;

use super::SharedState;

pub async fn jwks(State(state): State<SharedState>) -> Json<Value> {
    Json(state.signing_key.jwks_document())
}
