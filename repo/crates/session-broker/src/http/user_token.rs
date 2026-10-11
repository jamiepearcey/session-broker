//! `POST /session/token`: a signed-in user trades their session for a signed
//! token that downstream products (log-less, the console's own backends) can
//! verify offline against `/auth/jwks.json`.
//!
//! ```text
//! POST /session/token   {"audience": "logless", "tenant": "acme"}
//! 200  {"access_token", "token_type": "Bearer", "expires_in", "tenant", "roles", "indexes"}
//! ```
//!
//! Cookie-authenticated, so it is held to the same bar as every other
//! state-changing cookie route: INV-2 first, before anything is looked up. The
//! session must be `Active`, exactly as `/authz` and `/internal/token` require;
//! a stale generation is told to refresh first.
//!
//! **Tenant, roles and indexes come only from the broker's `user_grant` table**
//! for the session's subject. The request chooses an audience (from
//! `issuer_audiences`) and, for a user holding several grants, which tenant.
//! Nothing the identity provider sent is read. A subject the table has never
//! heard of gets `default_user_tenant` with `default_user_roles` when that is
//! configured, so a single-tenant install needs no admin step; a subject whose
//! every grant was revoked gets nothing, because revoking has to mean
//! something.
//!
//! `sid` is the broker's session id, never the cookie. The token lives for
//! `issuer_user_ttl_secs`, cut short at the session's idle expiry: a token
//! should not outlive the sign-in it came from by more than the idle window
//! the operator already accepts.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::error::{ApiError, ErrorCode};
use super::guards::{self, AllowDirectNavigation};
use super::{session, AppState};
use crate::audit::{action, ActorKind, Event, Outcome};
use crate::issuer::IssuerHandle;
use crate::session::Resolution;
use crate::token::TokenHash;

/// The metric's `kind` label.
const KIND: &str = "user";

#[derive(Deserialize)]
struct Request {
    audience: String,
    #[serde(default)]
    tenant: Option<String>,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    sid: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: &'a str,
    kind: &'a str,
    tenant: &'a str,
    roles: &'a [String],
    indexes: &'a [String],
}

#[derive(Serialize)]
struct Granted {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    tenant: String,
    roles: Vec<String>,
    indexes: Vec<String>,
}

/// What is known about the caller by the time the attempt ends, for the audit
/// row. Filled in as the checks pass.
#[derive(Default)]
struct Attempt {
    sub: Option<String>,
    sid: Option<String>,
    issued: Option<IssuedFacts>,
}

struct IssuedFacts {
    audience: String,
    tenant: String,
    kid: String,
    jti: String,
    ttl: u64,
}

pub async fn issue(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(handle) = &state.issuer else {
        state.metrics.record_token_issued(KIND, "lane_disabled");
        return ApiError::new(
            ErrorCode::LaneDisabled,
            "The token issuer is not configured: set token_issuer and issuer_audiences.",
        )
        .into_response();
    };
    let now = state.clock.now();
    let mut attempt = Attempt::default();

    match issue_inner(&state, handle, &headers, &body, &mut attempt) {
        Ok(granted) => {
            state.metrics.record_token_issued(KIND, "issued");
            if let (Some(sink), Some(sub), Some(facts)) =
                (&state.audit, &attempt.sub, &attempt.issued)
            {
                // Coalesced per (subject, audience), like machine issuance:
                // the fact worth keeping is that this user was drawing tokens
                // this afternoon, not each one. Refusals are never coalesced.
                if sink.should_record_issuance(sub, &facts.audience, now) {
                    let mut event =
                        Event::new(action::TOKEN_ISSUED, Outcome::Success, ActorKind::User, now)
                            .subject(sub.clone())
                            .detail(serde_json::json!({
                                "aud": facts.audience,
                                "kind": KIND,
                                "tenant": facts.tenant,
                                "kid": facts.kid,
                                "jti": facts.jti,
                                "ttl": facts.ttl,
                            }));
                    if let Some(sid) = &attempt.sid {
                        event = event.sid(sid.clone());
                    }
                    sink.record(event);
                }
            }
            (
                StatusCode::OK,
                [
                    (header::CACHE_CONTROL, "no-store"),
                    (header::PRAGMA, "no-cache"),
                ],
                axum::Json(granted),
            )
                .into_response()
        }
        Err(err) => {
            let code = serde_json::to_value(err.error)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "error".to_owned());
            state.metrics.record_token_issued(KIND, &code);
            // Recorded once there is a signed-in user to put in the row: a
            // forged request or a dead cookie is counted above and no more.
            // `unavailable` is the broker's own fault and is in the log.
            if let (Some(sink), Some(sub), false) = (
                &state.audit,
                &attempt.sub,
                err.error == ErrorCode::Unavailable,
            ) {
                let mut event = Event::new(
                    action::TOKEN_ISSUANCE_REFUSED,
                    Outcome::Failure,
                    ActorKind::User,
                    now,
                )
                .subject(sub.clone())
                .reason(code);
                if let Some(sid) = &attempt.sid {
                    event = event.sid(sid.clone());
                }
                sink.record(event);
            }
            err.into_response()
        }
    }
}

fn issue_inner(
    state: &AppState,
    handle: &IssuerHandle,
    headers: &HeaderMap,
    body: &[u8],
    attempt: &mut Attempt,
) -> Result<Granted, ApiError> {
    // INV-2, before the cookie or the body is looked at.
    guards::require_same_origin(headers, state.config.origin(), AllowDirectNavigation::No)?;

    let now = state.clock.now();
    let Some(cookie) = guards::cookie(headers, state.config.session_cookie_name()) else {
        return Err(session::unauthenticated(&state.config, None));
    };
    let hash = TokenHash::of(cookie);
    match state.sessions.resolve(&hash, now) {
        Resolution::Active { .. } => {}
        Resolution::StaleRefreshable { .. } => {
            return Err(ApiError::new(
                ErrorCode::SessionStale,
                "this session generation has aged out: refresh, then retry",
            ))
        }
        other => return Err(session::denial(other, &state.config, None)),
    }
    let Some(meta) = state.sessions.meta_for(&hash) else {
        return Err(session::unauthenticated(&state.config, None));
    };
    attempt.sub = Some(meta.sub.clone());
    attempt.sid = Some(meta.sid.clone());

    let request: Request = serde_json::from_slice(body).map_err(|_| {
        ApiError::new(
            ErrorCode::BadRequest,
            "the body must be JSON: {\"audience\": \"...\", \"tenant\": \"...\"}",
        )
    })?;
    let config = &handle.config;
    if !config.audiences.contains(&request.audience) {
        return Err(ApiError::new(
            ErrorCode::BadAudience,
            "this issuer does not issue tokens for that audience",
        ));
    }

    // --- what the user may have ----------------------------------------
    let grants = handle.signer.user_grants(&meta.sub).map_err(|e| {
        tracing::error!(target: "broker::issuer", error = %e, "user grant lookup failed");
        unavailable()
    })?;
    let (tenant, roles, indexes) = if grants.live.is_empty() && !grants.any_row {
        // Never granted anything: the install's default, if it has one.
        match (&config.default_user_tenant, &request.tenant) {
            (Some(default), asked) if asked.as_deref().is_none_or(|t| t == default) => {
                // The default is a grant the install makes for the user; a
                // tenant the operator disabled grants nothing.
                let disabled = handle.signer.tenant_is_disabled(default).map_err(|e| {
                    tracing::error!(target: "broker::issuer", error = %e, "tenant lookup failed");
                    unavailable()
                })?;
                if disabled {
                    return Err(not_granted());
                }
                (
                    default.clone(),
                    config.default_user_roles.clone(),
                    vec!["*".to_owned()],
                )
            }
            _ => return Err(not_granted()),
        }
    } else {
        let chosen = match request.tenant.as_deref() {
            Some(asked) => grants.live.iter().find(|g| g.tenant_id == asked),
            None => match grants.live.as_slice() {
                [only] => Some(only),
                [] => None,
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::BadRequest,
                        "this user holds several tenants: name one in \"tenant\"",
                    ))
                }
            },
        };
        let Some(grant) = chosen else {
            return Err(not_granted());
        };
        (
            grant.tenant_id.clone(),
            grant.roles.clone(),
            grant.indexes.clone(),
        )
    };

    // --- sign -----------------------------------------------------------
    // Cut short at the session's idle expiry. `Active` means `now` is before
    // it, so there is always at least a second left.
    let remaining = (meta.refresh_until - now.secs()).max(1) as u64;
    let ttl = config.user_ttl_secs.min(remaining);
    let mut jti_bytes = [0u8; 16];
    crate::token::fill_random(&mut jti_bytes);
    let jti = URL_SAFE_NO_PAD.encode(jti_bytes);
    let claims = Claims {
        iss: &config.issuer,
        sub: &meta.sub,
        sid: &meta.sid,
        aud: &request.audience,
        exp: now.plus_secs(ttl).secs(),
        iat: now.secs(),
        jti: &jti,
        kind: KIND,
        tenant: &tenant,
        roles: &roles,
        indexes: &indexes,
    };
    let (kid, access_token) = handle.signer.sign_with_kid(&claims).map_err(|e| {
        tracing::error!(target: "broker::issuer", error = %e, "token could not be signed");
        unavailable()
    })?;

    attempt.issued = Some(IssuedFacts {
        audience: request.audience,
        tenant: tenant.clone(),
        kid,
        jti,
        ttl,
    });
    Ok(Granted {
        access_token,
        token_type: "Bearer",
        expires_in: ttl,
        tenant,
        roles,
        indexes,
    })
}

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        "the token could not be issued right now; retry shortly",
    )
}

fn not_granted() -> ApiError {
    ApiError::new(
        ErrorCode::NotGranted,
        "this user has no grant for that tenant",
    )
}

#[cfg(test)]
mod tests;
