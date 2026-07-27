//! `POST /token` — `authorization_code` and `refresh_token` grants,
//! form-encoded, per RFC 6749 §4.1.3 / §6.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

use super::SharedState;
use crate::{
    error::OAuthError,
    state::{now_unix, AuthCodeError, RefreshError},
};

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub id_token: String,
    pub scope: String,
}

pub async fn token(State(state): State<SharedState>, Form(form): Form<TokenForm>) -> Response {
    let grant_type = form.grant_type.clone().unwrap_or_default();
    // Counted unconditionally, before latency/fail-next/validation: this is
    // the counter a broker's tests assert on to prove a code path did (or
    // didn't) reach the IdP at all, so it must reflect every call attempt.
    state.record_token_call(&grant_type);

    let latency_ms = state.runtime_config().token_latency_ms;
    if latency_ms > 0 {
        tokio::time::sleep(Duration::from_millis(latency_ms)).await;
    }

    if let Some((status, error, description)) = state.take_fail_next() {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return OAuthError::new(status, error)
            .maybe_description(description)
            .into_response();
    }

    let Some(client_id) = form.client_id.as_deref() else {
        return OAuthError::invalid_request("client_id is required").into_response();
    };
    let Some(client) = state.find_client(client_id) else {
        return OAuthError::invalid_client("unknown client_id").into_response();
    };
    if let Some(expected_secret) = client.client_secret.as_deref() {
        if form.client_secret.as_deref() != Some(expected_secret) {
            return OAuthError::invalid_client("missing or incorrect client_secret")
                .into_response();
        }
    }

    match grant_type.as_str() {
        "authorization_code" => authorization_code_grant(&state, &form, client_id).await,
        "refresh_token" => refresh_token_grant(&state, &form, client_id).await,
        "" => OAuthError::invalid_request("grant_type is required").into_response(),
        other => {
            OAuthError::invalid_request(format!("unsupported grant_type: {other}")).into_response()
        }
    }
}

async fn authorization_code_grant(
    state: &SharedState,
    form: &TokenForm,
    client_id: &str,
) -> Response {
    let (Some(code), Some(redirect_uri), Some(code_verifier)) = (
        form.code.as_deref(),
        form.redirect_uri.as_deref(),
        form.code_verifier.as_deref(),
    ) else {
        return OAuthError::invalid_request("code, redirect_uri, and code_verifier are required")
            .into_response();
    };

    let now = now_unix();
    let record = match state.redeem_auth_code(code, client_id, redirect_uri, code_verifier, now) {
        Ok(record) => record,
        Err(AuthCodeError::NotFound) => {
            return OAuthError::invalid_grant("unknown authorization code").into_response()
        }
        Err(AuthCodeError::AlreadyUsed) => {
            return OAuthError::invalid_grant("authorization code has already been used")
                .into_response()
        }
        Err(AuthCodeError::Expired) => {
            return OAuthError::invalid_grant("authorization code has expired").into_response()
        }
        Err(AuthCodeError::ClientMismatch) => {
            return OAuthError::invalid_grant("client_id does not match the authorization request")
                .into_response()
        }
        Err(AuthCodeError::RedirectUriMismatch) => {
            return OAuthError::invalid_grant(
                "redirect_uri does not match the authorization request",
            )
            .into_response()
        }
        Err(AuthCodeError::PkceMismatch) => {
            return OAuthError::invalid_grant("code_verifier does not match code_challenge")
                .into_response()
        }
    };

    let (access_token, expires_in) =
        state.issue_access_token(&record.subject, client_id, &record.scope, now);
    let refresh_token = state.issue_refresh_token(&record.subject, client_id, &record.scope, now);
    let id_token = match sign_id_token(
        state,
        &record.subject,
        client_id,
        record.nonce.as_deref(),
        now,
    ) {
        Ok(id_token) => id_token,
        Err(error) => return signing_failure(error),
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token,
        id_token,
        scope: record.scope,
    })
    .into_response()
}

async fn refresh_token_grant(state: &SharedState, form: &TokenForm, client_id: &str) -> Response {
    let Some(presented) = form.refresh_token.as_deref() else {
        return OAuthError::invalid_request("refresh_token is required").into_response();
    };

    let now = now_unix();
    let grant = match state.refresh_grant(presented, client_id, now) {
        Ok(grant) => grant,
        Err(RefreshError::NotFound) => {
            return OAuthError::invalid_grant("unknown refresh_token").into_response()
        }
        Err(RefreshError::Revoked) => {
            return OAuthError::invalid_grant("refresh_token has been revoked").into_response()
        }
        Err(RefreshError::Expired) => {
            return OAuthError::invalid_grant("refresh_token has expired").into_response()
        }
    };

    let (access_token, expires_in) =
        state.issue_access_token(&grant.subject, client_id, &grant.scope, now);
    // No nonce on a refreshed id_token: nonce only ever applies to the
    // id_token issued directly from the authorization request it came from.
    let id_token = match sign_id_token(state, &grant.subject, client_id, None, now) {
        Ok(id_token) => id_token,
        Err(error) => return signing_failure(error),
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: grant.refresh_token,
        id_token,
        scope: grant.scope,
    })
    .into_response()
}

#[derive(Debug, Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

fn sign_id_token(
    state: &SharedState,
    subject: &str,
    client_id: &str,
    nonce: Option<&str>,
    now: i64,
) -> anyhow::Result<String> {
    // id_token lifetime tracks the access-token TTL: there is no separate
    // knob for it in the spec's test-control surface, and access-token TTL
    // is the one the broker actually varies in its tests.
    let ttl = state.runtime_config().access_token_ttl_secs as i64;
    state.signing_key.sign(&IdTokenClaims {
        iss: &state.base_url,
        sub: subject,
        aud: client_id,
        exp: now + ttl,
        iat: now,
        nonce,
    })
}

fn signing_failure(error: anyhow::Error) -> Response {
    tracing::error!(%error, "failed to sign id_token");
    OAuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        .with_description(error.to_string())
        .into_response()
}
