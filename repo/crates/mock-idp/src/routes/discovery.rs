//! `GET /.well-known/openid-configuration`

use axum::{extract::State, Json};
use serde_json::{json, Value};

use super::SharedState;

pub async fn discovery(State(state): State<SharedState>) -> Json<Value> {
    let base = &state.base_url;
    let mut document = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "jwks_uri": format!("{base}/jwks.json"),
        "revocation_endpoint": format!("{base}/revoke"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    });
    if let Some(methods) = &state.token_auth_methods {
        document["token_endpoint_auth_methods_supported"] = json!(methods);
    }
    Json(document)
}
