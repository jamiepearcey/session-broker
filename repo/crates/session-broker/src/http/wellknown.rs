//! What a verifier fetches: the signing keys at `GET /auth/jwks.json` and the
//! issuer metadata (RFC 8414) at `GET /.well-known/oauth-authorization-server`.
//!
//! Both are public by design (the keys are public keys) and both are meant to
//! be cached, so they say so: `Cache-Control: public` with the configured
//! `max-age`, an `ETag` that makes a refresh a 304, and `stale-if-error` so a
//! verifier keeps serving from its copy while the broker is down. The
//! hardening layer only adds `no-store` to a response that has no
//! `Cache-Control` of its own, so these are not caught by it.
//!
//! Both answer `501 lane_disabled` until `token_issuer` and `issuer_audiences`
//! are configured.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::AppState;
use crate::issuer::IssuerHandle;

/// How long a verifier may keep using its copy when a refresh fails.
const STALE_IF_ERROR_SECS: u64 = 2_592_000;

pub async fn jwks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(handle) = &state.issuer else {
        return lane_disabled();
    };
    let doc = handle.signer.jwks();
    document(&state, handle, &headers, &doc)
}

pub async fn metadata(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(handle) = &state.issuer else {
        return lane_disabled();
    };
    // Only what exists.
    let doc = serde_json::json!({
        "issuer": handle.config.issuer,
        "jwks_uri": handle.config.jwks_uri,
        "token_endpoint": handle.config.token_endpoint,
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "response_types_supported": ["token"],
    });
    document(&state, handle, &headers, &doc)
}

fn document(
    state: &AppState,
    handle: &IssuerHandle,
    request: &HeaderMap,
    doc: &serde_json::Value,
) -> Response {
    let body = serde_json::to_vec(doc).unwrap_or_default();
    let etag = format!(
        "\"{}\"",
        URL_SAFE_NO_PAD.encode(&Sha256::digest(&body)[..12])
    );
    let cache_control = format!(
        "public, max-age={}, stale-if-error={STALE_IF_ERROR_SECS}",
        handle.config.jwks_max_age_secs
    );
    // Set by hand: the HTTP server adds `Date` itself, but a response built in
    // a test, or behind a layer that rebuilds it, would have none.
    let date = http_date(state.clock.now().secs());
    let status = if if_none_match(request, &etag) {
        StatusCode::NOT_MODIFIED
    } else {
        StatusCode::OK
    };
    let mut response = if status == StatusCode::OK {
        (status, body).into_response()
    } else {
        status.into_response()
    };
    let headers = response.headers_mut();
    if status == StatusCode::OK {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    for (name, value) in [
        (header::CACHE_CONTROL, cache_control),
        (header::ETAG, etag),
        (header::DATE, date),
    ] {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    }
    response
}

/// `If-None-Match` as a client sends it back: a list of entity tags, possibly
/// weak (`W/`), or `*`.
fn if_none_match(request: &HeaderMap, etag: &str) -> bool {
    request
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .map(str::trim)
                .any(|t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag)
        })
}

fn lane_disabled() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"error":"lane_disabled","detail":"The token issuer is not configured: set token_issuer and issuer_audiences."}"#,
    )
        .into_response()
}

/// RFC 9110 `IMF-fixdate`, e.g. `Tue, 14 Nov 2023 22:13:20 GMT`.
fn http_date(epoch_secs: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = epoch_secs.div_euclid(86_400);
    let secs = epoch_secs.rem_euclid(86_400);
    // Civil-from-days (Hinnant): days since 1970-01-01 to a proleptic Gregorian date.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days + 4).rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests;
