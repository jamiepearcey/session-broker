//! `POST /auth/token`: a service principal trades its secret for a signed
//! token (OAuth 2.0 client credentials, RFC 6749 §4.4).
//!
//! On the public listener, because the machines that call it (agents at the
//! edge) sit outside the operator network. The body is
//! `application/x-www-form-urlencoded` and nothing else: one shape to validate,
//! and the one every OAuth client library sends.
//!
//! ```text
//! grant_type=client_credentials&client_id=sp_…&client_secret=sbp_…[&scope=a b][&ttl=3600]
//! ```
//!
//! The id and secret may travel in HTTP Basic instead. The answer is RFC 6749
//! §5.1 (`access_token`, `token_type`, `expires_in`, `scope`); a refusal is
//! §5.2 (`error`, `error_description`).
//!
//! **Every claim comes from the principal's row.** The request chooses only a
//! narrower `scope` and a shorter `ttl`. There is no tenant or audience
//! parameter; one that is sent is ignored like any other unknown field.
//!
//! **One refusal for every dead credential.** An unknown id, a wrong secret, a
//! revoked or expired secret, a revoked principal and a disabled tenant all
//! answer the same `401 invalid_client` body, so the route cannot be used to
//! learn which of them is true.
//!
//! **Wrong credentials are budgeted per `client_id`**, not per client address,
//! so the limit works with no client-IP header configured. Ids that name no
//! principal share one budget between them. Only a failure
//! spends from the budget, and it is spent after the check: a principal with
//! the right secret is never locked out by someone else guessing against its
//! id. Past the budget a wrong guess answers 429 and is no longer recorded.

use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::Serialize;

use super::AppState;
use crate::audit::{action, ActorKind, Event, Outcome};
use crate::issuer::IssuerHandle;
use crate::ratelimit::Decision;

/// The metric's `kind` until the principal is known.
const KIND_UNKNOWN: &str = "machine";
/// The limiter bucket, and the `bucket` label when it trips.
const FAILURE_BUCKET: &str = "issuer_client";

/// Sent with every `invalid_client`, whichever way the credentials arrived:
/// RFC 6749 §5.2 wants a challenge on the 401.
const CHALLENGE: &str = r#"Basic realm="session-broker", charset="UTF-8""#;

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: &'a str,
    tenant: &'a str,
    kind: &'a str,
    name: &'a str,
    scopes: &'a [String],
    indexes: &'a [String],
}

#[derive(Serialize)]
struct Granted {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: &'static str,
}

struct Refusal {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
}

impl Refusal {
    fn invalid_request(description: &'static str) -> Refusal {
        Refusal {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description,
        }
    }

    /// One body for every reason a credential does not work.
    fn invalid_client() -> Refusal {
        Refusal {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: "Client authentication failed.",
        }
    }

    fn unavailable() -> Refusal {
        Refusal {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "temporarily_unavailable",
            description: "The token could not be issued right now. Retry shortly.",
        }
    }

    fn into_response(self) -> Response {
        respond(self.status, self.error, self.description)
    }
}

fn respond(status: StatusCode, error: &'static str, error_description: &'static str) -> Response {
    let mut response = (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(ErrorBody {
            error,
            error_description,
        }),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(CHALLENGE),
        );
    }
    response
}

/// What is known about the caller by the time the attempt ends, for the
/// metric and the audit row. Filled in as the checks pass.
#[derive(Default)]
struct Attempt {
    /// The presented `client_id`, kept only when it has the shape of a
    /// principal id: anything else is the caller's free text and has no place
    /// in the record or in a limiter key.
    client_id: Option<String>,
    /// The principal's kind, once its secret has resolved.
    kind: Option<String>,
    issued: Option<IssuedFacts>,
}

struct IssuedFacts {
    audience: String,
    tenant: String,
    kid: String,
    jti: String,
    ttl: u64,
}

pub async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let Some(handle) = &state.issuer else {
        state
            .metrics
            .record_token_issued(KIND_UNKNOWN, "lane_disabled");
        return respond(
            StatusCode::NOT_IMPLEMENTED,
            "lane_disabled",
            "The token issuer is not configured: set token_issuer and issuer_audiences.",
        );
    };
    let now = state.clock.now();
    let mut attempt = Attempt::default();
    let outcome = issue_inner(&state, handle, &headers, form, &mut attempt);
    let kind = attempt.kind.as_deref().unwrap_or(KIND_UNKNOWN);

    match outcome {
        Ok(granted) => {
            state.metrics.record_token_issued(kind, "issued");
            if let (Some(sink), Some(principal_id), Some(facts)) =
                (&state.audit, &attempt.client_id, &attempt.issued)
            {
                // Coalesced per (principal, audience): the fact worth keeping
                // is that this principal was drawing tokens this afternoon,
                // not each one it drew. Refusals below are never coalesced.
                if sink.should_record_issuance(principal_id, &facts.audience, now) {
                    sink.record(
                        Event::new(
                            action::TOKEN_ISSUED,
                            Outcome::Success,
                            ActorKind::Backend,
                            now,
                        )
                        .actor_id(principal_id.clone())
                        .key_id(principal_id.clone())
                        .detail(serde_json::json!({
                            "aud": facts.audience,
                            "kind": kind,
                            "tenant": facts.tenant,
                            "kid": facts.kid,
                            "jti": facts.jti,
                            "ttl": facts.ttl,
                        })),
                    );
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
        Err(refusal) => {
            // Only a credential failure spends from the budget. A principal
            // with the right secret asking for the wrong scope is not guessing.
            if refusal.error == "invalid_client" {
                if let Some(response) = spend_failure(&state, handle, &attempt) {
                    state.metrics.record_token_issued(kind, "rate_limited");
                    return response;
                }
            }
            state.metrics.record_token_issued(kind, refusal.error);
            // A request that never named a credential (a JSON body, a missing
            // grant_type) is counted above and not recorded: there is no "who"
            // to put in the row. `temporarily_unavailable` is the broker's own
            // fault and is in the log.
            let about_a_caller = !matches!(
                refusal.error,
                "invalid_request" | "unsupported_grant_type" | "temporarily_unavailable"
            ) || attempt.kind.is_some();
            if let (Some(sink), true) = (&state.audit, about_a_caller) {
                let mut event = Event::new(
                    action::TOKEN_ISSUANCE_REFUSED,
                    Outcome::Failure,
                    ActorKind::Backend,
                    now,
                )
                .reason(refusal.error);
                if let Some(id) = &attempt.client_id {
                    event = event.actor_id(id.clone()).key_id(id.clone());
                }
                sink.record(event);
            }
            refusal.into_response()
        }
    }
}

/// Count one wrong credential against its `client_id`. `Some(response)` means
/// the budget is spent: answer 429 instead of the 401.
fn spend_failure(state: &AppState, handle: &IssuerHandle, attempt: &Attempt) -> Option<Response> {
    let limiter = handle.client_failures.as_ref()?;
    // Only an id that names a principal gets a budget of its own. Anything
    // else, whether not shaped like an id or shaped right and issued to no
    // one, is text the caller made up, and a bucket per made-up string is a
    // fresh budget per request. They share one. A store error counts as
    // unknown: the failure is already being answered.
    let id = attempt
        .client_id
        .as_deref()
        .filter(|id| handle.signer.principal_exists(id).unwrap_or(false))
        .unwrap_or("unknown");
    let Decision::Deny { retry_after } = limiter.check(&format!("{FAILURE_BUCKET}:{id}")) else {
        return None;
    };
    let secs = retry_after.as_secs().max(1);
    state.metrics.record_rate_limited("public", FAILURE_BUCKET);
    tracing::warn!(
        target: "broker::ratelimit",
        lane = "public",
        bucket = FAILURE_BUCKET,
        client_id = id,
        retry_after_secs = secs,
        "rate limit tripped"
    );
    let mut response = respond(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "Too many failed attempts for this client. Retry after the interval in Retry-After.",
    );
    if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    Some(response)
}

fn issue_inner(
    state: &AppState,
    handle: &IssuerHandle,
    headers: &HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
    attempt: &mut Attempt,
) -> Result<Granted, Refusal> {
    let Form(fields) = form.map_err(|rejection| Refusal {
        status: match rejection.into_response().status() {
            StatusCode::PAYLOAD_TOO_LARGE => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        },
        error: "invalid_request",
        description: "The body must be application/x-www-form-urlencoded.",
    })?;

    // RFC 6749 §3.2: a parameter sent twice is an error, not a choice of which
    // one to believe. Names this route does not know (`tenant`, `audience`,
    // ...) are ignored.
    let field = |name: &str| -> Result<Option<&str>, Refusal> {
        let mut found = fields.iter().filter(|(k, _)| k == name).map(|(_, v)| v);
        let first = found.next();
        if found.next().is_some() {
            return Err(Refusal::invalid_request(
                "A parameter was sent more than once.",
            ));
        }
        Ok(first.map(String::as_str).filter(|v| !v.is_empty()))
    };

    match field("grant_type")? {
        Some("client_credentials") => {}
        Some(_) => {
            return Err(Refusal {
                status: StatusCode::BAD_REQUEST,
                error: "unsupported_grant_type",
                description: "Only grant_type=client_credentials is supported.",
            })
        }
        None => return Err(Refusal::invalid_request("grant_type is required.")),
    }
    let ttl = match field("ttl")? {
        Some(raw) => Some(
            raw.parse::<u64>()
                .ok()
                .filter(|secs| *secs > 0)
                .ok_or_else(|| {
                    Refusal::invalid_request("ttl must be a whole number of seconds, at least 1.")
                })?,
        ),
        None => None,
    };
    let requested_scope = field("scope")?;

    // --- who is asking --------------------------------------------------
    let body_id = field("client_id")?;
    let body_secret = field("client_secret")?;
    let basic = basic_credentials(headers)?;
    let (client_id, secret) = match (&basic, body_id, body_secret) {
        // RFC 6749 §2.3: one authentication method per request.
        (Some(_), _, Some(_)) => {
            return Err(Refusal::invalid_request(
                "Send the client secret in the Authorization header or in the body, not both.",
            ))
        }
        (Some((id, _)), Some(other), None) if id != other => {
            return Err(Refusal::invalid_request(
                "client_id in the body does not match the Authorization header.",
            ))
        }
        (Some((id, secret)), _, None) => (id.as_str(), secret.as_str()),
        (None, Some(id), Some(secret)) => (id, secret),
        (None, _, _) => return Err(Refusal::invalid_client()),
    };

    // Shape first, before any store read: the id is `sp_…`, the secret
    // `sbp_…`. A credential of another class (a backend key, an admin key) is
    // refused here without being hashed or looked up.
    if !is_principal_id(client_id) {
        return Err(Refusal::invalid_client());
    }
    attempt.client_id = Some(client_id.to_owned());
    if !secret.starts_with("sbp_") || secret.len() > 128 {
        return Err(Refusal::invalid_client());
    }

    let principal = match handle.signer.authenticate(secret) {
        Ok(Some(principal)) if principal.principal_id == client_id => principal,
        Ok(_) => return Err(Refusal::invalid_client()),
        Err(e) => {
            // Not `invalid_client`: the caller's secret may be perfectly good,
            // and an agent that is told otherwise stops retrying.
            tracing::error!(target: "broker::issuer", error = %e, "principal lookup failed");
            return Err(Refusal::unavailable());
        }
    };
    attempt.kind = Some(principal.kind.clone());

    // --- what it may have -----------------------------------------------
    let config = &handle.config;
    if !config.audiences.contains(&principal.audience) {
        return Err(Refusal {
            status: StatusCode::BAD_REQUEST,
            error: "unauthorized_client",
            description: "This principal's audience is not one this issuer is configured for \
                          (issuer_audiences).",
        });
    }

    let scopes: Vec<String> = match requested_scope {
        Some(requested) => {
            let mut narrowed: Vec<String> = Vec::new();
            for scope in requested.split(' ').filter(|s| !s.is_empty()) {
                if !principal.scopes.iter().any(|s| s == scope) {
                    return Err(Refusal {
                        status: StatusCode::BAD_REQUEST,
                        error: "invalid_scope",
                        description: "The requested scope is not one this principal holds.",
                    });
                }
                if !narrowed.iter().any(|s| s == scope) {
                    narrowed.push(scope.to_owned());
                }
            }
            if narrowed.is_empty() {
                principal.scopes.clone()
            } else {
                narrowed
            }
        }
        None => principal.scopes.clone(),
    };

    // The principal's own maximum, itself held to the issuer-wide one: a
    // retired signing key stays published only that long.
    let ceiling = principal.max_ttl_secs.min(config.max_ttl_secs);
    let ttl = match ttl {
        Some(asked) if asked > ceiling => {
            return Err(Refusal::invalid_request(
                "ttl is longer than this principal's maximum token lifetime.",
            ))
        }
        Some(asked) => asked,
        None => config.machine_ttl_secs.min(ceiling),
    };

    // --- sign -------------------------------------------------------------
    let now = state.clock.now();
    let mut jti_bytes = [0u8; 16];
    crate::token::fill_random(&mut jti_bytes);
    let jti = URL_SAFE_NO_PAD.encode(jti_bytes);
    let claims = Claims {
        iss: &config.issuer,
        sub: &principal.principal_id,
        aud: &principal.audience,
        exp: now.plus_secs(ttl).secs(),
        iat: now.secs(),
        jti: &jti,
        tenant: &principal.tenant_id,
        kind: &principal.kind,
        name: &principal.name,
        scopes: &scopes,
        indexes: &principal.indexes,
    };
    let (kid, access_token) = handle.signer.sign_with_kid(&claims).map_err(|e| {
        tracing::error!(target: "broker::issuer", error = %e, "token could not be signed");
        Refusal::unavailable()
    })?;

    handle.signer.record_use(&principal.principal_id);
    attempt.issued = Some(IssuedFacts {
        audience: principal.audience,
        tenant: principal.tenant_id,
        kid,
        jti,
        ttl,
    });
    Ok(Granted {
        access_token,
        token_type: "Bearer",
        expires_in: ttl,
        scope: scopes.join(" "),
    })
}

/// `sp_` and the id alphabet. Principal ids are `sp_` plus 16 base64url
/// characters; the bound is looser than that so a longer id format later does
/// not have to change this.
fn is_principal_id(value: &str) -> bool {
    value.len() <= 64
        && value.strip_prefix("sp_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// `Authorization: Basic base64(client_id:client_secret)`, if that is how the
/// caller authenticated. A Basic header that does not decode is a failed
/// authentication, not a missing one.
///
/// RFC 6749 §2.3.1 form-encodes both halves before the base64. Ids and secrets
/// here are base64url text, which that encoding leaves unchanged, so there is
/// nothing to decode.
fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, Refusal> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let encoded = value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .map(|(_, rest)| rest.trim())
        .ok_or_else(Refusal::invalid_client)?;
    let decoded = STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(Refusal::invalid_client)?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(Refusal::invalid_client)?;
    Ok(Some((id.to_owned(), secret.to_owned())))
}

#[cfg(test)]
mod tests;
