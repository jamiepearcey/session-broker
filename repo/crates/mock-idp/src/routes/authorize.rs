//! `GET /authorize` — authorization-code + PKCE, with no interactive login
//! UI: `login_as` picks which canned user "is" the logged-in subject,
//! defaulting to the first configured user.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use url::Url;

use super::SharedState;
use crate::state::{now_unix, AuthCode};

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    /// Subject of the canned user to "log in" as. Defaults to the first
    /// configured user when omitted.
    pub login_as: Option<String>,
    /// Extension beyond the base OIDC parameter set: a mock IdP has no real
    /// browser session to consult, so `prompt=none`'s "is there an active
    /// session" question has to be answered by the caller explicitly.
    /// Defaults to `true` so ordinary `/authorize` calls are unaffected;
    /// tests that want the `login_required` path pass `active_session=false`.
    pub active_session: Option<bool>,
}

pub async fn authorize(
    State(state): State<SharedState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    state.record_authorize_call();

    // client_id / redirect_uri are validated before anything else, and a
    // failure here is a direct error response rather than a redirect:
    // redirecting to an unregistered URI would make this endpoint an open
    // redirect.
    let Some(client_id) = params.client_id.as_deref() else {
        return bad_request("client_id is required");
    };
    let Some(client) = state.find_client(client_id) else {
        return bad_request("unknown client_id");
    };
    let Some(redirect_uri) = params.redirect_uri.as_deref() else {
        return bad_request("redirect_uri is required");
    };
    if !client
        .redirect_uris
        .iter()
        .any(|registered| registered == redirect_uri)
    {
        return bad_request("redirect_uri is not registered for this client");
    }

    // From here the redirect_uri is trusted, so every remaining failure is
    // reported by redirecting back with `error`/`error_description` rather
    // than rendering a page here (there is no page — no login UI).
    let state_param = params.state.as_deref();
    if params.response_type.as_deref() != Some("code") {
        return redirect_error(
            redirect_uri,
            state_param,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let Some(code_challenge) = params.code_challenge.as_deref() else {
        return redirect_error(
            redirect_uri,
            state_param,
            "invalid_request",
            "code_challenge is required",
        );
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return redirect_error(
            redirect_uri,
            state_param,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }

    let requested_subject = params
        .login_as
        .as_deref()
        .unwrap_or(&state.default_user().subject);
    let Some(user) = state.find_user(requested_subject) else {
        return redirect_error(
            redirect_uri,
            state_param,
            "invalid_request",
            "unknown login_as subject",
        );
    };

    let prompt_none = params
        .prompt
        .as_deref()
        .map(|prompt| prompt.split_whitespace().any(|value| value == "none"))
        .unwrap_or(false);
    if prompt_none && !params.active_session.unwrap_or(true) {
        return redirect_error(
            redirect_uri,
            state_param,
            "login_required",
            "no active session (active_session=false)",
        );
    }

    let now = now_unix();
    let code = crate::state::new_opaque_token("code");
    state.store_auth_code(
        code.clone(),
        AuthCode {
            client_id: client_id.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            subject: user.subject.clone(),
            scope: params.scope.clone().unwrap_or_else(|| "openid".to_owned()),
            nonce: params.nonce.clone(),
            code_challenge: code_challenge.to_owned(),
            expires_at: now + state.authorization_code_ttl_secs as i64,
            used: false,
        },
    );

    redirect_ok(redirect_uri, state_param, &code)
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_owned()).into_response()
}

fn redirect_ok(redirect_uri: &str, state: Option<&str>, code: &str) -> Response {
    let Ok(mut url) = Url::parse(redirect_uri) else {
        return bad_request("redirect_uri is not a valid URL");
    };
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    found(&url)
}

fn redirect_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    let Ok(mut url) = Url::parse(redirect_uri) else {
        return bad_request("redirect_uri is not a valid URL");
    };
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", description);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    found(&url)
}

/// A 302 Found redirect. Deliberately not `axum::response::Redirect::to`,
/// which answers with 303 See Other — the wrong status for an OAuth
/// authorization response and not what a broker's HTTP client expects here.
fn found(url: &Url) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url.as_str())]).into_response()
}
