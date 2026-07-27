//! The error taxonomy from `docs/architecture/implementation-strategy.md` §4.
//!
//! Every failure the HTTP surface can produce is one of these codes, rendered as
//! `{"error", "detail", "login_url"?}`. The client SDK branches on `error`, so
//! the codes are contract, not prose.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No cookie, or one this broker has forgotten entirely.
    InvalidSession,
    /// A generation past its resource life. Refresh, then retry.
    SessionStale,
    /// The session itself is over: idle, absolute, logged out, or upstream-revoked.
    SessionExpired,
    /// Interactive login is required and the caller asked for a non-redirect answer.
    LoginRequired,
    /// The upstream grant is dead, so no access token can be handed out.
    UpstreamRevoked,
    /// INV-2: the request failed the same-origin check.
    CsrfRejected,
    /// The upstream authorization flow failed or was tampered with.
    OauthError,
    BadRequest,
    RateLimited,
}

impl ErrorCode {
    pub fn status(self) -> StatusCode {
        match self {
            ErrorCode::InvalidSession
            | ErrorCode::SessionStale
            | ErrorCode::SessionExpired
            | ErrorCode::LoginRequired => StatusCode::UNAUTHORIZED,
            ErrorCode::CsrfRejected => StatusCode::FORBIDDEN,
            ErrorCode::UpstreamRevoked => StatusCode::CONFLICT,
            ErrorCode::OauthError | ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub error: ErrorCode,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
}

impl ApiError {
    pub fn new(error: ErrorCode, detail: impl Into<String>) -> ApiError {
        ApiError {
            error,
            detail: detail.into(),
            login_url: None,
        }
    }

    /// Attach the URL the app should navigate to in order to recover. Present on
    /// exactly the errors a client can act on, so the SDK never has to construct
    /// a login URL itself.
    pub fn with_login_url(mut self, url: impl Into<String>) -> ApiError {
        self.login_url = Some(url.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.error.status();
        let body = serde_json::to_string(&self).unwrap_or_else(|_| {
            r#"{"error":"bad_request","detail":"error serialisation failed"}"#.to_owned()
        });
        (
            status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response()
    }
}
