//! `/admin/*` — the management surface the console drives.
//!
//! Three things an operator needs and previously could not do without editing
//! config and restarting: see and rotate the backend API keys, see who is
//! signed in and cut a session off, and see whether the upstream grants behind
//! those sessions are healthy.
//!
//! ## Where it lives, and what guards it
//!
//! Mounted on the **internal listener** alongside `/internal/token`, never on
//! the public one. An endpoint that can mint a credential for acting as any
//! user must not be reachable from the internet, and a bind address is the
//! cheapest way to say so.
//!
//! Authenticated by a **separate** `admin_api_key`, not the backend key. A key
//! that can mint keys is strictly more powerful than one that can exchange a
//! session for a token; sharing one value between them would mean every backend
//! service in the deployment could also create credentials for itself.
//!
//! ## The one-shot secret
//!
//! `POST /admin/api-keys` returns the secret exactly once and stores only its
//! SHA-256. There is no endpoint that reveals an existing key, and adding one
//! would defeat the point: a leaked console database should expose *who holds
//! access*, not the access itself. Losing a key means issuing a new one.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::audit::{ActorKind, AuditSink, Event, Outcome};
use crate::clock::Clock;
use crate::session::SessionMap;
use crate::store::{repo, writer::WriterHandle, Reader};
use crate::telemetry::{LogControl, Metrics};

mod identity;

#[derive(Clone)]
pub struct AdminState {
    pub sessions: Arc<SessionMap>,
    pub reader: Arc<Reader>,
    pub writer: WriterHandle,
    pub clock: Arc<dyn Clock>,
    /// `None` disables the whole lane. An unconfigured admin surface that
    /// answered anyone would be the worst endpoint in the deployment.
    pub admin_key: Option<Arc<str>>,
    /// `None` only in the cookie/state-machine tests that have no store behind
    /// them. Production always supplies one — without it the mutations below
    /// would proceed unrecorded, which ADR-0015 exists to prevent.
    pub audit: Option<AuditSink>,
    /// The runtime verbosity control. `None` in tests that never install a
    /// subscriber.
    pub log: Option<Arc<LogControl>>,
    pub metrics: Arc<Metrics>,
    /// Limits WRONG-key attempts (M6). `None` in tests.
    pub rate_limit: Option<crate::http::guards::RateLimit>,
    /// The token issuer's signing keys. `None` when they could not be loaded
    /// at boot, and in tests that do not exercise them.
    pub issuer: Option<Arc<crate::issuer::Issuer>>,
}

/// The admin actor for an audited row.
///
/// There is no admin *identity* — the lane is guarded by one shared secret
/// (ADR-0015 does not change that), so the honest actor id is the credential,
/// not a person. Recording `admin` with no id would be a lie of omission;
/// recording a name nobody authenticated would be worse.
const ADMIN_ACTOR: &str = "admin_api_key";

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: &'static str,
}

fn refuse(status: StatusCode, error: &'static str, detail: &'static str) -> Response {
    (status, Json(ErrorBody { error, detail })).into_response()
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/api-keys", get(list_keys).post(create_key))
        .route("/admin/api-keys/{key_id}", delete(revoke_key))
        .route("/admin/sessions", get(list_sessions))
        .route("/admin/sessions/{sid}", delete(revoke_session))
        .route("/admin/custody", get(list_custody))
        .route("/admin/signing-keys", get(identity::list_signing_keys))
        .route("/admin/signing-keys/rotate", post(rotate_signing_key))
        .route(
            "/admin/tenants",
            get(identity::list_tenants).post(identity::create_tenant),
        )
        .route("/admin/tenants/{tenant}", delete(identity::disable_tenant))
        .route(
            "/admin/principals",
            get(identity::list_principals).post(identity::create_principal),
        )
        .route(
            "/admin/principals/{principal_id}",
            get(identity::get_principal).delete(identity::revoke_principal),
        )
        .route(
            "/admin/principals/{principal_id}/secrets",
            post(identity::add_secret),
        )
        .route(
            "/admin/principals/{principal_id}/secrets/{secret_id}",
            delete(identity::revoke_secret),
        )
        .route(
            "/admin/user-grants",
            get(identity::list_user_grants).post(identity::create_user_grant),
        )
        .route(
            "/admin/user-grants/{sub}/{tenant}",
            delete(identity::revoke_user_grant),
        )
        .route("/admin/audit", get(list_audit))
        .route(
            "/admin/observability",
            get(get_observability)
                .put(put_log_level)
                .delete(restore_log_level),
        )
        .with_state(state)
}

/// Every handler starts here. Returns the response to send on refusal.
///
/// `Box`ed because an `axum::Response` is a large `Err` variant to carry
/// around by value on every call.
/// Every handler starts here.
///
/// Rate limiting is applied to FAILURES only, deliberately. A console polling
/// its own views with a valid key is ordinary traffic and must not be throttled;
/// what needs a ceiling is guessing, and only a wrong key is a guess. It also
/// means an operator can never lock themselves out by using the tool normally.
fn authorised(
    state: &AdminState,
    headers: &HeaderMap,
    peer: Option<&std::net::SocketAddr>,
) -> Result<(), Box<Response>> {
    let Some(expected) = state.admin_key.as_deref() else {
        return Err(Box::new(refuse(
            StatusCode::NOT_IMPLEMENTED,
            "lane_disabled",
            "No admin_api_key is configured, so the admin lane is disabled.",
        )));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match presented {
        Some(key) if crate::http::internal::key_matches(key, expected) => Ok(()),
        _ => {
            if let Some(limit) = &state.rate_limit {
                if let Some(response) = limit.check(peer, headers, "admin_auth") {
                    return Err(Box::new(response));
                }
            }
            Err(Box::new(refuse(
                StatusCode::UNAUTHORIZED,
                "unauthorised",
                "A valid admin API key is required.",
            )))
        }
    }
}

// --- API keys -----------------------------------------------------------

#[derive(Debug, Serialize)]
struct ApiKeyView {
    key_id: String,
    name: String,
    created_at: i64,
    created_by: Option<String>,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
    /// Derived rather than stored, so the console and the token lane cannot
    /// disagree about what "live" means.
    live: bool,
}

async fn list_keys(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    match state.reader.with(repo::list_api_keys) {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| ApiKeyView {
                    key_id: r.key_id,
                    name: r.name,
                    created_at: r.created_at.secs(),
                    created_by: r.created_by,
                    last_used_at: r.last_used_at.map(|t| t.secs()),
                    revoked_at: r.revoked_at.map(|t| t.secs()),
                    live: r.revoked_at.is_none(),
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "admin: listing api keys failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "The key list could not be read.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateKeyRequest {
    /// Which backend this key is for. Required, and the reason the list is
    /// worth reading at all — five keys named "key" answer nothing during an
    /// incident.
    name: String,
}

#[derive(Debug, Serialize)]
struct CreateKeyResponse {
    key_id: String,
    name: String,
    /// Shown exactly once. Not recoverable.
    secret: String,
    created_at: i64,
}

async fn create_key(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
    Json(request): Json<CreateKeyRequest>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }

    let name = request.name.trim();
    if name.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "name_required",
            "A key must say which backend it is for.",
        );
    }

    let key_id = format!("bk_{}", short_id());
    let secret = crate::oauth::random_id();
    let hash = hash_secret(&secret);
    let now = state.clock.now();

    // Tier A (ADR-0015): the audit row rides the same command and lands in the
    // same transaction. `detail` carries the name — never the secret, which is
    // in this response and nowhere else, by design.
    let audit_row = state.audit.as_ref().map(|sink| {
        sink.transactional(
            Event::new(
                crate::audit::action::KEY_ISSUED,
                Outcome::Success,
                ActorKind::Admin,
                now,
            )
            .actor_id(ADMIN_ACTOR)
            .key_id(key_id.clone())
            .detail(serde_json::json!({ "name": name })),
        )
    });

    // Write-through: a key handed to an operator that did not reach the
    // database would appear to work until the next request and then fail
    // permanently, which is the most confusing possible outcome.
    let created = state.writer.write_admin_audited(
        crate::store::writer::AdminWrite::InsertApiKey {
            key_id: key_id.clone(),
            name: name.to_owned(),
            key_hash: hash,
            created_by: None,
            now,
        },
        audit_row,
    );
    if let Err(e) = created {
        // The transaction carried both, so neither happened. Refusing here is
        // the fail-closed half of ADR-0015: no credential is ever issued
        // without a record of it having been issued.
        if let Some(sink) = &state.audit {
            sink.note_transactional_failure();
        }
        tracing::error!(error = %e, "admin: creating an api key failed");
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            "The key could not be stored, so it was not issued.",
        );
    }

    tracing::info!(key_id = %key_id, name = %name, "admin: api key issued");
    (
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            key_id,
            name: name.to_owned(),
            secret,
            created_at: now.secs(),
        }),
    )
        .into_response()
}

async fn revoke_key(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let audit_row = state.audit.as_ref().map(|sink| {
        sink.transactional(
            Event::new(
                crate::audit::action::KEY_REVOKED,
                Outcome::Success,
                ActorKind::Admin,
                now,
            )
            .actor_id(ADMIN_ACTOR)
            .key_id(key_id.clone()),
        )
    });

    match state.writer.write_admin_audited(
        crate::store::writer::AdminWrite::RevokeApiKey {
            key_id: key_id.clone(),
            now,
        },
        audit_row,
    ) {
        Ok(true) => {
            tracing::info!(key_id = %key_id, "admin: api key revoked");
            StatusCode::NO_CONTENT.into_response()
        }
        // Reported rather than swallowed: "revoked" and "there was nothing to
        // revoke" must not look the same to someone racing to cut off access.
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_key",
            "No live key with that id.",
        ),
        Err(e) => {
            tracing::error!(error = %e, "admin: revoking an api key failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "The key could not be revoked.",
            )
        }
    }
}

// --- sessions -----------------------------------------------------------

#[derive(Debug, Serialize)]
struct SessionView {
    sid: String,
    sub: String,
    custody_id: String,
    current_gen: u32,
    idle_exp: i64,
    absolute_exp: i64,
}

async fn list_sessions(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    // Read from the STORE, not the in-memory map: the map holds token hashes,
    // and an admin surface has no business anywhere near credential material
    // even in hashed form.
    match state.reader.with(repo::rehydrate) {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|entry| SessionView {
                    sid: entry.session.sid.0,
                    sub: entry.session.sub,
                    custody_id: entry.session.custody_id.0,
                    current_gen: entry.session.current_gen,
                    idle_exp: entry.session.idle_exp.secs(),
                    absolute_exp: entry.session.absolute_exp.secs(),
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "admin: listing sessions failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "Sessions could not be read.",
            )
        }
    }
}

/// Force-logout. Kills every generation at once (INV-7), in memory and durably.
async fn revoke_session(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let sid = crate::session::Sid(sid);

    // The in-memory tombstone is what takes effect immediately and what
    // enqueues the durable write. A session that has been swept from memory but
    // is still `alive` on disk would otherwise come back on the next restart,
    // so the durable write is issued regardless of the memory hit.
    // Named as an administrative action, so the client's event stream can say
    // "an administrator ended this session" rather than the misleading "you
    // logged out" (ADR-0013).
    let killed = state.sessions.tombstone_session_with_reason(
        &sid,
        now,
        crate::session::KillReason::AdminRevoked,
    );
    if !killed {
        state
            .writer
            .enqueue(crate::store::writer::Command::TombstoneSession(
                sid.clone(),
                now,
            ));
    }

    // Tier A by classification, but it cannot ride the tombstone the way a key
    // mutation rides its `AdminWrite`: the kill has already taken effect in
    // memory by the time we get here, and INV-7 requires that it does — the
    // user must be out *now*, not after a transaction commits. So the row is
    // enqueued rather than transactional, and this is the one place the two
    // tiers do not line up with the ADR's table. Recording it as the operator
    // action it is still matters more than the tier it lands in.
    if let Some(sink) = &state.audit {
        sink.record(
            Event::new(
                crate::audit::action::SESSION_REVOKED,
                Outcome::Success,
                ActorKind::Admin,
                now,
            )
            .actor_id(ADMIN_ACTOR)
            .sid(sid.0.clone())
            .detail(serde_json::json!({ "in_memory": killed })),
        );
    }

    tracing::info!(sid = %sid.0, in_memory = killed, "admin: session revoked");
    StatusCode::NO_CONTENT.into_response()
}

// --- audit trail --------------------------------------------------------

#[derive(Debug, Serialize)]
struct AuditView {
    seq: i64,
    at: i64,
    action: String,
    outcome: String,
    actor_kind: String,
    actor_id: Option<String>,
    subject: Option<String>,
    sid: Option<String>,
    custody_id: Option<String>,
    key_id: Option<String>,
    reason: Option<String>,
    client_ip_prefix: Option<String>,
    /// Passed through as parsed JSON so the console does not have to
    /// double-decode a string that is already structured.
    detail: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct AuditParams {
    since: Option<i64>,
    until: Option<i64>,
    /// Prefix, so `action=key.` finds both `key.issued` and `key.revoked`.
    action: Option<String>,
    subject: Option<String>,
    outcome: Option<String>,
    actor_kind: Option<String>,
    before_seq: Option<i64>,
    limit: Option<u32>,
    /// `ndjson` for export; anything else is a JSON envelope.
    format: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditPage {
    rows: Vec<AuditView>,
    /// Cursor for the next page, or `null` at the end. Derived from the last
    /// row rather than an offset: rows are only ever appended, so an offset
    /// would drift under a concurrent write and a `seq` cursor cannot.
    next_before_seq: Option<i64>,
    /// Window and health, so the view can say "history starts here" instead of
    /// letting an empty result read as "nothing happened".
    retention_days: u32,
    rows_total: i64,
    oldest_at: Option<i64>,
    newest_at: Option<i64>,
    gaps: i64,
}

async fn list_audit(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<AuditParams>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }

    let query = repo::AuditQuery {
        since: params.since.map(crate::clock::Timestamp),
        until: params.until.map(crate::clock::Timestamp),
        action_prefix: params.action.filter(|s| !s.is_empty()),
        subject: params.subject.filter(|s| !s.is_empty()),
        outcome: params.outcome.filter(|s| !s.is_empty()),
        actor_kind: params.actor_kind.filter(|s| !s.is_empty()),
        before_seq: params.before_seq,
        limit: params.limit.unwrap_or(200),
    };

    let loaded = state.reader.with(|conn| {
        repo::list_audit(conn, &query).and_then(|r| Ok((r, repo::audit_stats(conn)?)))
    });
    let (rows, stats) = match loaded {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "admin: reading the audit trail failed");
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "The audit trail could not be read.",
            );
        }
    };

    let next_before_seq = (rows.len() as u32 >= query.limit.clamp(1, 1000))
        .then(|| rows.last().map(|r| r.seq))
        .flatten();

    let views: Vec<AuditView> = rows
        .into_iter()
        .map(|stored| AuditView {
            seq: stored.seq,
            at: stored.row.at.secs(),
            action: stored.row.action,
            outcome: stored.row.outcome,
            actor_kind: stored.row.actor_kind,
            actor_id: stored.row.actor_id,
            subject: stored.row.subject,
            sid: stored.row.sid,
            custody_id: stored.row.custody_id,
            key_id: stored.row.key_id,
            reason: stored.row.reason,
            client_ip_prefix: stored.row.client_ip_prefix,
            detail: stored
                .row
                .detail
                .and_then(|d| serde_json::from_str(&d).ok()),
        })
        .collect();

    if params.format.as_deref() == Some("ndjson") {
        // One JSON object per line: what every log tool and SIEM importer
        // already reads, and streamable — an export of 90 days should not have
        // to be a single array held in memory at both ends.
        let mut body = String::new();
        for view in &views {
            if let Ok(line) = serde_json::to_string(view) {
                body.push_str(&line);
                body.push('\n');
            }
        }
        return (
            [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
            body,
        )
            .into_response();
    }

    Json(AuditPage {
        rows: views,
        next_before_seq,
        retention_days: state
            .audit
            .as_ref()
            .map(|a| a.config().retention_days)
            .unwrap_or(0),
        rows_total: stats.rows,
        oldest_at: stats.oldest_at.map(|t| t.secs()),
        newest_at: stats.newest_at.map(|t| t.secs()),
        gaps: stats.gaps,
    })
    .into_response()
}

// --- observability ------------------------------------------------------

#[derive(Debug, Serialize)]
struct ObservabilityView {
    log_format: String,
    /// What the deployment configured.
    configured_filter: String,
    /// What is actually in force, which differs while an override is running.
    effective_filter: String,
    /// Where lines go. Names, not paths to be edited from here — the console
    /// cannot change a sink (ADR-0015 §"Runtime controls").
    sinks: Vec<String>,
    log_file: Option<String>,
    log_file_rotation: Option<String>,
    override_active: bool,
    override_expires_at: Option<i64>,
    override_requested_by: Option<String>,
    override_max_secs: u64,
    metrics_path: Option<String>,
    audit_retention_days: u32,
    audit_queue_capacity: usize,
    audit_queue_depth: i64,
    audit_coalesce_secs: u64,
    audit_subject_mode: String,
    audit_record_rotations: bool,
    audit_rows: i64,
    audit_oldest_at: Option<i64>,
    audit_newest_at: Option<i64>,
    audit_gaps: i64,
    audit_dropped_total: u64,
    audit_failed_total: u64,
}

async fn get_observability(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }

    let stats = state.reader.with(repo::audit_stats).unwrap_or_default();
    let audit_config = state
        .audit
        .as_ref()
        .map(|a| a.config().clone())
        .unwrap_or_default();
    let current = state.log.as_ref().and_then(|l| l.current_override());

    let (log_format, configured_filter, effective_filter, log_file, rotation, override_max) =
        match &state.log {
            Some(log) => (
                log.config().format.as_str().to_owned(),
                log.config().default_filter.clone(),
                log.effective_filter(),
                log.config().file.as_ref().map(|p| p.display().to_string()),
                Some(log.config().file_rotation.as_str().to_owned()),
                log.config().override_max_secs,
            ),
            // A broker whose subscriber was installed by something else (a test
            // harness) reports that honestly rather than inventing defaults that
            // do not describe the running process.
            None => (
                "unknown".to_owned(),
                "unknown".to_owned(),
                "unknown".to_owned(),
                None,
                None,
                0,
            ),
        };

    let mut sinks = vec!["stdout".to_owned()];
    if log_file.is_some() {
        sinks.push("file".to_owned());
    }

    Json(ObservabilityView {
        log_format,
        configured_filter,
        effective_filter,
        sinks,
        log_file,
        log_file_rotation: rotation,
        override_active: current.is_some(),
        override_expires_at: current.as_ref().map(|o| o.expires_at),
        override_requested_by: current.and_then(|o| o.requested_by),
        override_max_secs: override_max,
        metrics_path: Some("/metrics".to_owned()),
        audit_retention_days: audit_config.retention_days,
        audit_queue_capacity: audit_config.queue_capacity,
        audit_queue_depth: state.audit.as_ref().map(|a| a.depth()).unwrap_or(0),
        audit_coalesce_secs: audit_config.coalesce_secs,
        audit_subject_mode: audit_config.subject_mode.as_str().to_owned(),
        audit_record_rotations: audit_config.record_rotations,
        audit_rows: stats.rows,
        audit_oldest_at: stats.oldest_at.map(|t| t.secs()),
        audit_newest_at: stats.newest_at.map(|t| t.secs()),
        audit_gaps: stats.gaps,
        audit_dropped_total: state.metrics.audit_dropped_total(),
        audit_failed_total: state.metrics.audit_failed_total(),
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct LogLevelRequest {
    /// An `EnvFilter` directive, not just a level: `session_broker::keepalive=trace`
    /// is the shape an operator actually wants during an incident, and refusing
    /// it would send them to a restart instead.
    filter: String,
    duration_secs: u64,
}

/// Raise (or lower) verbosity for a bounded window.
///
/// The window is the point. Diagnostics turned up during an incident and never
/// turned back down is the normal outcome of a level switch with no deadline,
/// and on a service that logs per platform request the cost of that is real.
async fn put_log_level(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
    Json(request): Json<LogLevelRequest>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let Some(log) = &state.log else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "no_log_control",
            "This process did not install its own subscriber, so verbosity cannot be changed here.",
        );
    };
    let now = state.clock.now();

    match log.set_override(
        &request.filter,
        request.duration_secs,
        now.secs(),
        Some(ADMIN_ACTOR.to_owned()),
    ) {
        Ok(entry) => {
            // Audited: changing how much the broker records is itself a
            // security-relevant act, and it is the one an attacker who reached
            // this console would want first.
            if let Some(sink) = &state.audit {
                sink.record(
                    Event::new(
                        crate::audit::action::LOGGING_LEVEL_CHANGED,
                        Outcome::Success,
                        ActorKind::Admin,
                        now,
                    )
                    .actor_id(ADMIN_ACTOR)
                    .detail(serde_json::json!({
                        "filter": entry.filter,
                        "expires_at": entry.expires_at,
                    })),
                );
            }
            Json(serde_json::json!({
                "filter": entry.filter,
                "expires_at": entry.expires_at,
            }))
            .into_response()
        }
        Err(crate::telemetry::LogControlError::BadFilter(_)) => refuse(
            StatusCode::BAD_REQUEST,
            "bad_filter",
            "That is not a valid tracing filter directive.",
        ),
        Err(crate::telemetry::LogControlError::TooLong { .. }) => refuse(
            StatusCode::BAD_REQUEST,
            "duration_out_of_range",
            "The duration must be between 1 second and the configured ceiling.",
        ),
        Err(crate::telemetry::LogControlError::Detached) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "reload_failed",
            "The subscriber would not accept the new filter.",
        ),
    }
}

/// Put the configured filter back now, rather than waiting for the deadline.
async fn restore_log_level(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let Some(log) = &state.log else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "no_log_control",
            "This process did not install its own subscriber, so verbosity cannot be changed here.",
        );
    };
    let now = state.clock.now();
    match log.restore() {
        Ok(changed) => {
            if changed {
                if let Some(sink) = &state.audit {
                    sink.record(
                        Event::new(
                            crate::audit::action::LOGGING_LEVEL_CHANGED,
                            Outcome::Success,
                            ActorKind::Admin,
                            now,
                        )
                        .actor_id(ADMIN_ACTOR)
                        .detail(serde_json::json!({
                            "filter": log.config().default_filter,
                            "restored": true,
                        })),
                    );
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "admin: restoring the log filter failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "reload_failed",
                "The configured filter could not be restored.",
            )
        }
    }
}

// --- custody ------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CustodyView {
    custody_id: String,
    status: String,
    access_exp: i64,
    next_refresh: i64,
    fail_count: i64,
}

async fn list_custody(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    match state.reader.with(repo::live_custody_schedules) {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| CustodyView {
                    custody_id: r.custody_id.0,
                    status: format!("{:?}", r.status).to_lowercase(),
                    access_exp: r.access_exp.secs(),
                    next_refresh: r.next_refresh.secs(),
                    fail_count: r.fail_count,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "admin: listing custody failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "Custody state could not be read.",
            )
        }
    }
}

// --- signing keys -------------------------------------------------------

/// Longest publish lead a rotation may ask for. A key scheduled further out
/// than this is a typo, not a plan.
const MAX_ROTATE_LEAD_SECS: u64 = 30 * 86_400;

#[derive(Debug, Default, Deserialize)]
struct RotateSigningKeyRequest {
    /// Seconds until the new key starts signing. Absent: the default publish
    /// lead (a day). `0`: now, and every older key is unpublished now.
    activate_in_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RotateSigningKeyResponse {
    #[serde(flatten)]
    rotation: crate::issuer::Rotation,
    /// What an operator should expect to happen next, in words.
    note: &'static str,
}

/// `POST /admin/signing-keys/rotate`. The body is optional.
async fn rotate_signing_key(
    State(state): State<AdminState>,
    crate::http::guards::PeerAddr(peer): crate::http::guards::PeerAddr,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let Some(issuer) = &state.issuer else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "lane_disabled",
            "The signing keys could not be loaded at start, so they cannot be rotated here.",
        );
    };
    let request: RotateSigningKeyRequest =
        if body.iter().all(u8::is_ascii_whitespace) {
            RotateSigningKeyRequest::default()
        } else {
            match serde_json::from_slice(&body) {
                Ok(request) => request,
                Err(_) => return refuse(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "The body must be empty or a JSON object with an optional activate_in_secs.",
                ),
            }
        };
    if request
        .activate_in_secs
        .is_some_and(|secs| secs > MAX_ROTATE_LEAD_SECS)
    {
        return refuse(
            StatusCode::BAD_REQUEST,
            "activate_in_out_of_range",
            "activate_in_secs must be at most 2592000 (30 days).",
        );
    }

    // The Tier A row (`signing_key.rotated`) rides the same transaction inside
    // `Issuer::rotate`, so a store failure refuses the rotation outright.
    match issuer.rotate(request.activate_in_secs, ADMIN_ACTOR) {
        Ok(rotation) => {
            let note = if rotation.immediate {
                "The new key signs now and every older key is no longer published. Tokens \
                 issued before this are invalid, and verifiers reject new tokens until they \
                 next refresh their key set."
            } else {
                "The new key is published now and starts signing at activate_at. Older keys \
                 stay published until previous_retire_at."
            };
            (
                StatusCode::CREATED,
                Json(RotateSigningKeyResponse { rotation, note }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "admin: rotating the signing key failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "The new key could not be stored, so nothing was rotated.",
            )
        }
    }
}

// --- helpers ------------------------------------------------------------

pub(crate) fn hash_secret(secret: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

fn short_id() -> String {
    crate::oauth::random_id().chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{TestClock, Timestamp};
    use crate::session::SessionPolicy;
    use crate::store::writer::Writer;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const T0: Timestamp = Timestamp(1_700_000_000);
    const ADMIN_KEY: &str = "an-admin-key-that-is-at-least-32-chars";

    /// File-backed, not `:memory:`. Two in-memory connections are two SEPARATE
    /// databases, so a key written through the writer would be invisible to the
    /// reader — and this lane's whole point is that a write on one connection
    /// is readable on the other.
    fn temp_db() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "session-broker-admin-test-{}-{:?}.sqlite3",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    /// A harness whose admin lane is rate-limited, keyed on a header so the
    /// test can present distinct "clients" without needing real sockets.
    fn limited_harness(admin_key: &str, burst: u32) -> (Router, Writer) {
        let path = temp_db();
        let _ = std::fs::remove_file(&path);
        let keyfile = path.with_extension("key");
        let conn = crate::store::open(&path, &keyfile).unwrap();
        let reader_conn = crate::store::open(&path, &keyfile).unwrap();
        let writer = Writer::spawn(conn);
        let metrics = crate::telemetry::Metrics::new();
        let state = AdminState {
            sessions: Arc::new(SessionMap::new(SessionPolicy::default())),
            reader: Arc::new(Reader::new(reader_conn)),
            writer: writer.handle(),
            clock: Arc::new(TestClock::new(T0)),
            admin_key: Some(Arc::from(admin_key)),
            audit: None,
            log: None,
            metrics: metrics.clone(),
            rate_limit: Some(crate::http::guards::RateLimit {
                limiter: Arc::new(crate::ratelimit::Limiter::new(
                    crate::ratelimit::Quota::new(burst, 60),
                    128,
                )),
                source: crate::ratelimit::ClientSource::Header("x-real-ip".to_owned()),
                metrics,
                lane: "admin",
            }),
            issuer: None,
        };
        (router(state), writer)
    }

    fn req_from(ip: &str, key: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/admin/api-keys")
            .header("x-real-ip", ip)
            .header("authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .unwrap()
    }

    /// Guessing the admin key must run out of attempts.
    #[tokio::test]
    async fn repeated_wrong_admin_keys_are_rate_limited_with_a_retry_after() {
        let (app, _writer) = limited_harness(ADMIN_KEY, 3);

        for i in 0..3 {
            let r = app
                .clone()
                .oneshot(req_from("203.0.113.5", "wrong"))
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "guess {i} is refused on its merits"
            );
        }

        let r = app
            .clone()
            .oneshot(req_from("203.0.113.5", "wrong"))
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "past the burst the guess never reaches the comparison at all"
        );
        assert!(
            r.headers().contains_key(axum::http::header::RETRY_AFTER),
            "a 429 without Retry-After tells a client nothing but 'try again sometime'"
        );
    }

    /// The property that makes this safe to enable: one attacker must not be
    /// able to lock the real operator out.
    #[tokio::test]
    async fn an_exhausted_attacker_does_not_lock_out_a_different_client() {
        let (app, _writer) = limited_harness(ADMIN_KEY, 2);

        for _ in 0..3 {
            let _ = app
                .clone()
                .oneshot(req_from("198.51.100.9", "wrong"))
                .await
                .unwrap();
        }
        let attacker = app
            .clone()
            .oneshot(req_from("198.51.100.9", "wrong"))
            .await
            .unwrap();
        assert_eq!(attacker.status(), StatusCode::TOO_MANY_REQUESTS);

        let operator = app
            .clone()
            .oneshot(req_from("203.0.113.1", ADMIN_KEY))
            .await
            .unwrap();
        assert_eq!(
            operator.status(),
            StatusCode::OK,
            "a different client with the RIGHT key is unaffected"
        );
    }

    /// Only failures count. A console polling with a valid key is ordinary
    /// traffic, and throttling it would mean an operator could lock themselves
    /// out by using the tool normally.
    #[tokio::test]
    async fn a_valid_key_is_never_throttled_however_often_it_is_used() {
        let (app, _writer) = limited_harness(ADMIN_KEY, 2);

        for i in 0..20 {
            let r = app
                .clone()
                .oneshot(req_from("203.0.113.1", ADMIN_KEY))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK, "valid request {i} must pass");
        }
    }

    fn harness(admin_key: Option<&str>) -> (Router, Writer) {
        let path = temp_db();
        let _ = std::fs::remove_file(&path);
        let keyfile = path.with_extension("key");
        let conn = crate::store::open(&path, &keyfile).unwrap();
        let reader_conn = crate::store::open(&path, &keyfile).unwrap();
        let writer = Writer::spawn(conn);
        let metrics = crate::telemetry::Metrics::new();
        let state = AdminState {
            sessions: Arc::new(SessionMap::new(SessionPolicy::default())),
            reader: Arc::new(Reader::new(reader_conn)),
            writer: writer.handle(),
            clock: Arc::new(TestClock::new(T0)),
            admin_key: admin_key.map(Arc::from),
            audit: Some(crate::audit::AuditSink::new(
                writer.handle(),
                metrics.clone(),
                crate::audit::AuditConfig::default(),
            )),
            // No subscriber is installed in unit tests, so the verbosity
            // endpoints answer 501 here — which is the behaviour those tests
            // assert, and the behaviour a process that did not install one
            // should have.
            log: None,
            metrics,
            rate_limit: None,
            issuer: None,
        };
        (router(state), writer)
    }

    fn req(method: &str, uri: &str, key: Option<&str>, body: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(k) = key {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        if body.is_some() {
            b = b.header("content-type", "application/json");
        }
        b.body(
            body.map(|s| Body::from(s.to_owned()))
                .unwrap_or(Body::empty()),
        )
        .unwrap()
    }

    async fn json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn a_created_key_shows_its_secret_once_and_never_again() {
        let (router, _w) = harness(Some(ADMIN_KEY));

        let created = router
            .clone()
            .oneshot(req(
                "POST",
                "/admin/api-keys",
                Some(ADMIN_KEY),
                Some(r#"{"name":"qp-omsd"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let body = json(created).await;
        let secret = body["secret"]
            .as_str()
            .expect("secret returned once")
            .to_owned();
        assert!(!secret.is_empty());

        // The list must never carry it back. This is the property that makes a
        // readable console database survivable.
        let listed = router
            .oneshot(req("GET", "/admin/api-keys", Some(ADMIN_KEY), None))
            .await
            .unwrap();
        let rows = json(listed).await;
        assert_eq!(rows[0]["name"], "qp-omsd");
        assert_eq!(rows[0]["live"], true);
        assert!(
            !rows.to_string().contains(&secret),
            "the secret must not be recoverable from the list"
        );
    }

    #[tokio::test]
    async fn revoking_twice_reports_the_second_as_unknown() {
        let (router, _w) = harness(Some(ADMIN_KEY));
        let created = router
            .clone()
            .oneshot(req(
                "POST",
                "/admin/api-keys",
                Some(ADMIN_KEY),
                Some(r#"{"name":"qp-api"}"#),
            ))
            .await
            .unwrap();
        let key_id = json(created).await["key_id"].as_str().unwrap().to_owned();

        let first = router
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/admin/api-keys/{key_id}"),
                Some(ADMIN_KEY),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::NO_CONTENT);

        // "Revoked" and "there was nothing to revoke" must not look alike to
        // someone racing to cut off access.
        let second = router
            .oneshot(req(
                "DELETE",
                &format!("/admin/api-keys/{key_id}"),
                Some(ADMIN_KEY),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn every_route_refuses_without_the_admin_key() {
        let (router, _w) = harness(Some(ADMIN_KEY));
        for (method, uri) in ALL_ROUTES {
            let response = router
                .clone()
                .oneshot(req(method, uri, None, None))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} must require the admin key"
            );
        }

        // The backend key is deliberately NOT sufficient here: a key that can
        // mint keys is more powerful than one that exchanges session tokens.
        let wrong = router
            .oneshot(req(
                "GET",
                "/admin/api-keys",
                Some("some-backend-key"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }

    /// Every route on the lane, one entry each. A new route that is not listed
    /// here is not covered by the refusal tests, so add it.
    const ALL_ROUTES: [(&str, &str); 22] = [
        ("GET", "/admin/api-keys"),
        ("DELETE", "/admin/api-keys/bk_x"),
        ("GET", "/admin/sessions"),
        ("DELETE", "/admin/sessions/sid_x"),
        ("GET", "/admin/custody"),
        ("GET", "/admin/signing-keys"),
        ("POST", "/admin/signing-keys/rotate"),
        ("GET", "/admin/tenants"),
        ("POST", "/admin/tenants"),
        ("DELETE", "/admin/tenants/acme"),
        ("GET", "/admin/principals"),
        ("POST", "/admin/principals"),
        ("GET", "/admin/principals/sp_x"),
        ("DELETE", "/admin/principals/sp_x"),
        ("POST", "/admin/principals/sp_x/secrets"),
        ("DELETE", "/admin/principals/sp_x/secrets/sps_x"),
        ("GET", "/admin/user-grants"),
        ("POST", "/admin/user-grants"),
        ("DELETE", "/admin/user-grants/alice/acme"),
        ("GET", "/admin/audit"),
        ("GET", "/admin/observability"),
        ("DELETE", "/admin/observability"),
    ];

    /// The admin lane with the signing keys behind it, as `main` builds it:
    /// bootstrapped, so one key already exists. Returns the database path so a
    /// test can look at the rows through a connection of its own.
    fn issuer_harness() -> (Router, Writer, std::path::PathBuf) {
        let lane = lane();
        (lane.router, lane._writer, lane.path)
    }

    struct Lane {
        router: Router,
        _writer: Writer,
        path: std::path::PathBuf,
        clock: TestClock,
    }

    fn lane() -> Lane {
        let path = temp_db().with_extension("issuer.sqlite3");
        let _ = std::fs::remove_file(&path);
        let keyfile = path.with_extension("key");
        let conn = crate::store::open(&path, &keyfile).unwrap();
        let reader = Arc::new(Reader::new(crate::store::open(&path, &keyfile).unwrap()));
        let writer = Writer::spawn(conn);
        let metrics = crate::telemetry::Metrics::new();
        let test_clock = TestClock::new(T0);
        let clock: Arc<dyn Clock> = Arc::new(test_clock.clone());
        let audit = crate::audit::AuditSink::new(
            writer.handle(),
            metrics.clone(),
            crate::audit::AuditConfig::default(),
        );
        let issuer = crate::issuer::bootstrap(
            reader.clone(),
            writer.handle(),
            Some(audit.clone()),
            clock.clone(),
            crate::issuer::KeyPolicy::default(),
        )
        .unwrap();
        let state = AdminState {
            sessions: Arc::new(SessionMap::new(SessionPolicy::default())),
            reader,
            writer: writer.handle(),
            clock,
            admin_key: Some(Arc::from(ADMIN_KEY)),
            audit: Some(audit),
            log: None,
            metrics,
            rate_limit: None,
            issuer: Some(issuer),
        };
        Lane {
            router: router(state),
            _writer: writer,
            path,
            clock: test_clock,
        }
    }

    fn signing_keys(path: &std::path::Path) -> Vec<repo::SigningKeyRow> {
        let conn = crate::store::open(path, &path.with_extension("key")).unwrap();
        repo::list_signing_keys(&conn).unwrap()
    }

    fn audit_actions(path: &std::path::Path, action: &str) -> Vec<repo::StoredAuditRow> {
        let conn = crate::store::open(path, &path.with_extension("key")).unwrap();
        repo::list_audit(
            &conn,
            &repo::AuditQuery {
                limit: 100,
                ..repo::AuditQuery::default()
            },
        )
        .unwrap()
        .into_iter()
        .filter(|r| r.row.action == action)
        .collect()
    }

    /// The route is the admin lane's one sender of `RotateSigningKey`. Observed
    /// through a separate connection: the new key is there, pending, the old
    /// one has an end date, and the record of it committed too.
    #[tokio::test]
    async fn rotating_over_the_admin_lane_stores_a_pending_key_and_records_it() {
        let (router, _w, path) = issuer_harness();
        let first = signing_keys(&path);
        assert_eq!(first.len(), 1);

        // No body at all: the default lead of a day.
        let response = router
            .clone()
            .oneshot(req(
                "POST",
                "/admin/signing-keys/rotate",
                Some(ADMIN_KEY),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = json(response).await;
        assert_eq!(body["activate_at"], T0.secs() + 86_400);
        assert_eq!(
            body["previous_retire_at"],
            T0.secs() + 86_400 + 86_400 + 300
        );
        assert_eq!(body["immediate"], false);

        let keys = signing_keys(&path);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid, body["kid"].as_str().unwrap());
        assert_eq!(keys[0].activate_at, T0.plus_secs(86_400));
        assert_eq!(keys[0].retire_at, None);
        assert_eq!(keys[1].kid, first[0].kid);
        assert_eq!(keys[1].retire_at, Some(T0.plus_secs(2 * 86_400 + 300)));

        let recorded = audit_actions(&path, crate::audit::action::SIGNING_KEY_ROTATED);
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].row.key_id.as_deref(),
            Some(keys[0].kid.as_str())
        );
        assert_eq!(recorded[0].row.actor_id.as_deref(), Some(ADMIN_ACTOR));

        // An explicit zero is the emergency form.
        let response = router
            .oneshot(req(
                "POST",
                "/admin/signing-keys/rotate",
                Some(ADMIN_KEY),
                Some(r#"{"activate_in_secs":0}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = json(response).await;
        assert_eq!(body["immediate"], true);
        assert_eq!(body["activate_at"], T0.secs());
        assert_eq!(signing_keys(&path).len(), 3);
    }

    #[tokio::test]
    async fn a_rotation_request_that_makes_no_sense_changes_nothing() {
        let (router, _w, path) = issuer_harness();
        for body in [r#"{"activate_in_secs":2592001}"#, "not json"] {
            let response = router
                .clone()
                .oneshot(req(
                    "POST",
                    "/admin/signing-keys/rotate",
                    Some(ADMIN_KEY),
                    Some(body),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }
        // And neither the admin key's absence nor a backend key gets through.
        for key in [None, Some("some-backend-key")] {
            let response = router
                .clone()
                .oneshot(req("POST", "/admin/signing-keys/rotate", key, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(signing_keys(&path).len(), 1);
        assert!(audit_actions(&path, crate::audit::action::SIGNING_KEY_ROTATED).is_empty());
    }

    /// Without the keys loaded the route says so; it does not pretend to rotate.
    #[tokio::test]
    async fn rotation_without_an_issuer_is_refused_as_disabled() {
        let (router, _w) = harness(Some(ADMIN_KEY));
        let response = router
            .oneshot(req(
                "POST",
                "/admin/signing-keys/rotate",
                Some(ADMIN_KEY),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // --- tenants, principals, secrets, user grants -----------------------

    async fn call(
        lane: &Lane,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let body = body.map(|b| b.to_string());
        let response = lane
            .router
            .clone()
            .oneshot(req(method, uri, Some(ADMIN_KEY), body.as_deref()))
            .await
            .unwrap();
        (response.status(), json(response).await)
    }

    /// A connection of the test's own, so what it sees is what committed.
    fn fresh(lane: &Lane) -> rusqlite::Connection {
        crate::store::open(&lane.path, &lane.path.with_extension("key")).unwrap()
    }

    /// Who a presented secret authenticates as right now, by the lookup the
    /// token lane will use.
    fn resolves(lane: &Lane, secret: &str) -> Option<String> {
        repo::find_live_principal_by_secret(&fresh(lane), &hash_secret(secret), lane.clock.now())
            .unwrap()
            .map(|p| p.principal_id)
    }

    fn audit_rows(lane: &Lane, action: &str) -> Vec<repo::StoredAuditRow> {
        audit_actions(&lane.path, action)
    }

    fn ingest_body(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "tenant": "acme",
            "kind": "ingest",
            "scopes": ["ingest"],
            "indexes": ["main", "audit"],
            "audience": "logless",
        })
    }

    /// Returns (principal_id, first secret).
    async fn new_principal(lane: &Lane, name: &str) -> (String, String) {
        let (status, body) = call(lane, "POST", "/admin/principals", Some(ingest_body(name))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (
            body["principal_id"].as_str().unwrap().to_owned(),
            body["secret"]["secret"].as_str().unwrap().to_owned(),
        )
    }

    #[tokio::test]
    async fn a_tenant_can_be_created_listed_and_disabled() {
        let l = lane();
        let (status, body) = call(
            &l,
            "POST",
            "/admin/tenants",
            Some(serde_json::json!({"tenant": "acme", "display_name": " Acme Ltd "})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["tenant"], "acme");
        assert_eq!(body["display_name"], "Acme Ltd");

        // The second create is a conflict, not a silent success.
        let (status, body) = call(
            &l,
            "POST",
            "/admin/tenants",
            Some(serde_json::json!({"tenant": "acme"})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "tenant_exists");

        let (_, listed) = call(&l, "GET", "/admin/tenants", None).await;
        let names: Vec<_> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["tenant"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["acme", "default"]);
        assert!(listed[0]["live"].as_bool().unwrap());

        let (status, _) = call(&l, "DELETE", "/admin/tenants/acme", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = call(&l, "DELETE", "/admin/tenants/acme", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "unknown_tenant");

        // Seen through a second connection.
        let tenants = repo::list_tenants(&fresh(&l)).unwrap();
        assert_eq!(tenants[0].disabled_at, Some(T0));
        let (_, listed) = call(&l, "GET", "/admin/tenants", None).await;
        assert_eq!(listed[0]["live"], false);

        // One row per attempt, newest first; the refused create is a failure.
        let created = audit_rows(&l, crate::audit::action::TENANT_CREATED);
        assert_eq!(created.len(), 2);
        assert_eq!(created[0].row.outcome, "failure");
        assert_eq!(created[0].row.reason.as_deref(), Some("conflict"));
        assert_eq!(created[1].row.outcome, "success");
        assert_eq!(
            audit_rows(&l, crate::audit::action::TENANT_DISABLED).len(),
            2
        );
    }

    #[tokio::test]
    async fn a_created_principal_shows_its_secret_once_and_stores_only_a_hash() {
        let l = lane();
        let (status, body) = call(&l, "POST", "/admin/principals", Some(ingest_body("edge"))).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = body["principal_id"].as_str().unwrap().to_owned();
        let secret = body["secret"]["secret"].as_str().unwrap().to_owned();
        assert!(id.starts_with("sp_"), "{id}");
        assert!(secret.starts_with("sbp_"), "{secret}");
        assert_eq!(secret.len(), 4 + 43, "32 random bytes, base64url");
        assert_eq!(body["secret"]["expires_at"], serde_json::Value::Null);
        assert_eq!(body["tenant"], "acme");
        assert_eq!(body["indexes"], serde_json::json!(["main", "audit"]));
        assert_eq!(body["max_ttl_secs"], 30 * 86_400);
        assert_eq!(body["created_by"], ADMIN_ACTOR);

        // Never again: not in the list, not in the single read.
        let (_, listed) = call(&l, "GET", "/admin/principals", None).await;
        let (_, one) = call(&l, "GET", &format!("/admin/principals/{id}"), None).await;
        assert!(!listed.to_string().contains(&secret));
        assert!(!one.to_string().contains(&secret));
        assert_eq!(listed[0]["principal_id"], id);
        assert_eq!(one["secrets"].as_array().unwrap().len(), 1);
        assert_eq!(one["secrets"][0]["secret_id"], body["secret"]["secret_id"]);
        assert_eq!(one["secrets"][0]["live"], true);

        // At rest: the SHA-256 and nothing else, and the audit rows do not
        // carry it either (INV-12).
        let conn = fresh(&l);
        let stored: Vec<u8> = conn
            .query_row(
                "SELECT secret_hash FROM principal_secret WHERE principal_id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, hash_secret(&secret));
        assert!(!stored.windows(secret.len()).any(|w| w == secret.as_bytes()));
        let hex: String = stored.iter().map(|b| format!("{b:02x}")).collect();
        for row in audit_rows(&l, crate::audit::action::PRINCIPAL_CREATED) {
            let all = format!("{:?}", row.row);
            assert!(!all.contains(&secret) && !all.contains(&hex));
        }

        // Naming the tenant made it.
        let (_, tenants) = call(&l, "GET", "/admin/tenants", None).await;
        assert_eq!(tenants[0]["tenant"], "acme");
        assert_eq!(resolves(&l, &secret).as_deref(), Some(id.as_str()));
    }

    #[tokio::test]
    async fn principals_are_listed_filtered_and_revoked_once() {
        let l = lane();
        let (a, secret_a) = new_principal(&l, "a").await;
        let mut other = ingest_body("b");
        other["tenant"] = "globex".into();
        let (status, _) = call(&l, "POST", "/admin/principals", Some(other)).await;
        assert_eq!(status, StatusCode::CREATED);

        let (_, all) = call(&l, "GET", "/admin/principals", None).await;
        assert_eq!(all.as_array().unwrap().len(), 2);
        let (_, acme) = call(&l, "GET", "/admin/principals?tenant=acme", None).await;
        assert_eq!(acme.as_array().unwrap().len(), 1);
        assert_eq!(acme[0]["principal_id"], a);

        let (status, _) = call(&l, "DELETE", &format!("/admin/principals/{a}"), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = call(&l, "DELETE", &format!("/admin/principals/{a}"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "unknown_principal");
        let (_, one) = call(&l, "GET", &format!("/admin/principals/{a}"), None).await;
        assert_eq!(one["live"], false);
        assert!(one["revoked_at"].is_i64());
        let (status, _) = call(&l, "GET", "/admin/principals/sp_missing", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The secret row is still live; the principal being revoked is what
        // stops it, and it stops at once.
        let live_secrets: i64 = fresh(&l)
            .query_row(
                "SELECT count(*) FROM principal_secret WHERE principal_id = ?1 AND revoked_at IS NULL",
                [&a],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(live_secrets, 1);
        assert_eq!(resolves(&l, &secret_a), None);

        // A revoked principal takes no further secrets.
        let (status, _) = call(&l, "POST", &format!("/admin/principals/{a}/secrets"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_duplicate_name_is_refused_and_leaves_nothing_behind() {
        let l = lane();
        new_principal(&l, "edge").await;
        let (status, body) = call(&l, "POST", "/admin/principals", Some(ingest_body("edge"))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "principal_exists");
        assert!(body.get("secret").is_none());

        let conn = fresh(&l);
        let count = |table: &str| -> i64 {
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count("principal"), 1);
        assert_eq!(
            count("principal_secret"),
            1,
            "no secret for the refused one"
        );
        let rows = audit_rows(&l, crate::audit::action::PRINCIPAL_CREATED);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].row.outcome, "failure", "newest first");
        assert_eq!(rows[0].row.reason.as_deref(), Some("conflict"));
        assert_eq!(rows[1].row.outcome, "success");
    }

    /// Rotation is "add, swap, revoke": adding must not disturb the old one.
    #[tokio::test]
    async fn adding_a_secret_leaves_two_live_and_each_revokes_alone() {
        let l = lane();
        let (id, first) = new_principal(&l, "edge").await;

        let (status, added) =
            call(&l, "POST", &format!("/admin/principals/{id}/secrets"), None).await;
        assert_eq!(status, StatusCode::CREATED);
        let second = added["secret"].as_str().unwrap().to_owned();
        let second_id = added["secret_id"].as_str().unwrap().to_owned();
        assert!(second.starts_with("sbp_"));
        assert_ne!(first, second);
        assert_eq!(added["expires_at"], serde_json::Value::Null);
        assert_eq!(added["old_secrets_expire_at"], serde_json::Value::Null);

        assert_eq!(resolves(&l, &first).as_deref(), Some(id.as_str()));
        assert_eq!(resolves(&l, &second).as_deref(), Some(id.as_str()));
        let (_, one) = call(&l, "GET", &format!("/admin/principals/{id}"), None).await;
        let live = one["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["live"] == true)
            .count();
        assert_eq!(live, 2);
        assert!(!one.to_string().contains(&second));

        // Revoke the new one: the old one is untouched.
        let uri = format!("/admin/principals/{id}/secrets/{second_id}");
        let (status, _) = call(&l, "DELETE", &uri, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(resolves(&l, &second), None);
        assert_eq!(resolves(&l, &first).as_deref(), Some(id.as_str()));
        let (status, body) = call(&l, "DELETE", &uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "unknown_secret");

        // A secret id from another principal is not this one's to revoke.
        let (other, _) = new_principal(&l, "other").await;
        let (status, _) = call(
            &l,
            "DELETE",
            &format!("/admin/principals/{other}/secrets/{second_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// The predicate pair: inside the window the secret resolves, at
    /// `expires_at` it does not.
    #[tokio::test]
    async fn a_secret_with_an_expiry_stops_working_when_the_clock_reaches_it() {
        let l = lane();
        let (id, forever) = new_principal(&l, "edge").await;
        let (_, added) = call(
            &l,
            "POST",
            &format!("/admin/principals/{id}/secrets"),
            Some(serde_json::json!({"expires_in_secs": 100})),
        )
        .await;
        let timed = added["secret"].as_str().unwrap().to_owned();
        assert_eq!(added["expires_at"], T0.secs() + 100);

        l.clock.set(T0.plus_secs(99));
        assert_eq!(resolves(&l, &timed).as_deref(), Some(id.as_str()), "inside");
        l.clock.set(T0.plus_secs(100));
        assert_eq!(resolves(&l, &timed), None, "at expires_at");
        l.clock.set(T0.plus_secs(10_000_000));
        assert_eq!(resolves(&l, &timed), None, "long after");
        assert_eq!(
            resolves(&l, &forever).as_deref(),
            Some(id.as_str()),
            "a secret with no expiry never lapses"
        );
        let (_, one) = call(&l, "GET", &format!("/admin/principals/{id}"), None).await;
        let lives: Vec<_> = one["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["live"].as_bool().unwrap())
            .collect();
        assert_eq!(lives, [false, true], "newest first; the listing agrees");
    }

    /// `expire_old_in_secs` dates the older secrets; it never lengthens one and
    /// never touches the new secret.
    #[tokio::test]
    async fn expiring_the_old_secrets_only_ever_moves_their_end_earlier() {
        let l = lane();
        let (id, a) = new_principal(&l, "edge").await;
        let add = |body: serde_json::Value| {
            let l = &l;
            let uri = format!("/admin/principals/{id}/secrets");
            async move {
                let (status, b) = call(l, "POST", &uri, Some(body)).await;
                assert_eq!(status, StatusCode::CREATED, "{b}");
                b
            }
        };

        let b = add(serde_json::json!({"expire_old_in_secs": 50})).await;
        assert_eq!(b["old_secrets_expire_at"], T0.secs() + 50);
        let b = b["secret"].as_str().unwrap().to_owned();
        // 10 s is earlier than 50 s, so a and b are pulled in; c is not an
        // "old" secret and keeps its own 500 s.
        let c = add(serde_json::json!({"expires_in_secs": 500, "expire_old_in_secs": 10})).await;
        let c = c["secret"].as_str().unwrap().to_owned();
        // 1000 s is later than every date so far: nothing moves.
        let d = add(serde_json::json!({"expire_old_in_secs": 1000})).await;
        let d = d["secret"].as_str().unwrap().to_owned();

        let live = |l: &Lane| [&a, &b, &c, &d].map(|s| resolves(l, s).is_some()).to_vec();
        l.clock.set(T0.plus_secs(9));
        assert_eq!(live(&l), [true, true, true, true]);
        l.clock.set(T0.plus_secs(10));
        assert_eq!(live(&l), [false, false, true, true], "a and b end at +10");
        l.clock.set(T0.plus_secs(499));
        assert_eq!(live(&l), [false, false, true, true]);
        l.clock.set(T0.plus_secs(500));
        assert_eq!(
            live(&l),
            [false, false, false, true],
            "c keeps its own date"
        );
        l.clock.set(T0.plus_secs(5_000));
        assert_eq!(live(&l), [false, false, false, true], "d was never dated");

        // And 0 means now.
        let e = add(serde_json::json!({"expire_old_in_secs": 0})).await;
        let e = e["secret"].as_str().unwrap().to_owned();
        assert_eq!(resolves(&l, &d), None);
        assert!(resolves(&l, &e).is_some());
    }

    #[tokio::test]
    async fn a_disabled_tenant_takes_its_principals_with_it() {
        let l = lane();
        let (id, secret) = new_principal(&l, "edge").await;
        assert_eq!(resolves(&l, &secret).as_deref(), Some(id.as_str()));

        let (status, _) = call(&l, "DELETE", "/admin/tenants/acme", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        assert_eq!(resolves(&l, &secret), None, "the tenant is the gate");
        let (_, one) = call(&l, "GET", &format!("/admin/principals/{id}"), None).await;
        assert_eq!(one["live"], true, "the principal itself is untouched");

        // Naming it again does not bring it back, for principals or grants.
        let (status, body) =
            call(&l, "POST", "/admin/principals", Some(ingest_body("again"))).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("tenant_disabled"))
        );
        let (status, body) = call(
            &l,
            "POST",
            "/admin/user-grants",
            Some(serde_json::json!({"sub": "alice", "tenant": "acme", "roles": ["viewer"]})),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("tenant_disabled"))
        );
        assert_eq!(resolves(&l, &secret), None);
    }

    #[tokio::test]
    async fn user_grants_are_created_listed_revoked_and_can_be_granted_again() {
        let l = lane();
        let grant = serde_json::json!({
            "sub": "auth0|abc@example.com", "tenant": "acme", "roles": ["viewer", "viewer", "editor"],
        });
        let (status, body) = call(&l, "POST", "/admin/user-grants", Some(grant.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["roles"], serde_json::json!(["viewer", "editor"]));
        assert_eq!(body["indexes"], serde_json::json!(["*"]));

        let (status, body) = call(&l, "POST", "/admin/user-grants", Some(grant.clone())).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("grant_exists"))
        );

        let (_, listed) = call(&l, "GET", "/admin/user-grants?tenant=acme", None).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        let (_, none) = call(&l, "GET", "/admin/user-grants?sub=nobody", None).await;
        assert!(none.as_array().unwrap().is_empty());
        let (_, by_sub) = call(
            &l,
            "GET",
            "/admin/user-grants?sub=auth0%7Cabc%40example.com",
            None,
        )
        .await;
        assert_eq!(by_sub.as_array().unwrap().len(), 1);

        let uri = "/admin/user-grants/auth0%7Cabc%40example.com/acme";
        let (status, _) = call(&l, "DELETE", uri, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = call(&l, "DELETE", uri, None).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("unknown_grant"))
        );
        let stored = repo::list_user_grants(&fresh(&l), None, None).unwrap();
        assert_eq!(stored[0].sub, "auth0|abc@example.com");
        assert_eq!(stored[0].revoked_at, Some(T0));

        // The (sub, tenant) key must not be spent by a revocation.
        let mut again = grant;
        again["roles"] = serde_json::json!(["admin"]);
        again["indexes"] = serde_json::json!(["main"]);
        let (status, _) = call(&l, "POST", "/admin/user-grants", Some(again)).await;
        assert_eq!(status, StatusCode::CREATED);
        let stored = repo::list_user_grants(&fresh(&l), None, None).unwrap();
        assert_eq!(stored.len(), 1, "revived in place");
        assert_eq!(stored[0].roles, ["admin"]);
        assert_eq!(stored[0].indexes, ["main"]);
        assert_eq!(stored[0].revoked_at, None);
    }

    #[tokio::test]
    async fn requests_that_make_no_sense_are_refused_and_change_nothing() {
        let l = lane();
        let with = |field: &str, value: serde_json::Value| {
            let mut body = ingest_body("edge");
            body[field] = value;
            body
        };
        let too_many: Vec<String> = (0..65).map(|i| format!("idx{i}")).collect();
        let cases = [
            (with("tenant", "Acme".into()), "invalid_tenant"),
            (with("tenant", "-acme".into()), "invalid_tenant"),
            (with("name", "has space".into()), "invalid_name"),
            (with("name", "".into()), "invalid_name"),
            (with("kind", "root".into()), "invalid_kind"),
            (with("scopes", serde_json::json!([])), "invalid_scopes"),
            (
                with("indexes", serde_json::json!(too_many)),
                "invalid_indexes",
            ),
            (with("indexes", serde_json::json!([""])), "invalid_indexes"),
            (with("audience", "two words".into()), "invalid_audience"),
            (with("max_ttl_secs", 0.into()), "max_ttl_out_of_range"),
            (
                with("max_ttl_secs", 31_536_001u64.into()),
                "max_ttl_out_of_range",
            ),
            (with("expires_in_secs", 0.into()), "expiry_out_of_range"),
            // A typo must not quietly land the principal in `default`.
            (with("tenant_id", "acme".into()), "bad_request"),
        ];
        for (body, error) in cases {
            let (status, got) = call(&l, "POST", "/admin/principals", Some(body.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(got["error"], error, "{body}");
        }
        let mut full = ingest_body("edge");
        full["max_ttl_secs"] = 31_536_000u64.into();
        full["indexes"] = serde_json::json!(["*"]);
        let (status, _) = call(&l, "POST", "/admin/principals", Some(full)).await;
        assert_eq!(status, StatusCode::CREATED, "the limits are inclusive");

        for body in [
            serde_json::json!({"sub": "", "roles": ["viewer"]}),
            serde_json::json!({"sub": "alice", "roles": []}),
            serde_json::json!({"sub": "alice", "roles": ["viewer"], "tenant": "Bad"}),
            serde_json::json!({"sub": "alice", "roles": ["viewer"], "extra": 1}),
        ] {
            let (status, _) = call(&l, "POST", "/admin/user-grants", Some(body.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
        for body in [
            serde_json::json!({"tenant": "NOPE"}),
            serde_json::json!({"tenant": "ok", "display_name": ""}),
        ] {
            let (status, _) = call(&l, "POST", "/admin/tenants", Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (id, _) = new_principal(&l, "x").await;
        for body in [
            serde_json::json!({"expires_in_secs": 0}),
            serde_json::json!({"expire_old_in_secs": 315_360_001u64}),
        ] {
            let uri = format!("/admin/principals/{id}/secrets");
            let (status, _) = call(&l, "POST", &uri, Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        // Only the two valid principals exist, and no secret was added.
        let conn = fresh(&l);
        let principals: i64 = conn
            .query_row("SELECT count(*) FROM principal", [], |r| r.get(0))
            .unwrap();
        let grants: i64 = conn
            .query_row("SELECT count(*) FROM user_grant", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            principals, 2,
            "the inclusive-limits one and the secrets one"
        );
        assert_eq!(grants, 0);
        assert!(audit_rows(&l, crate::audit::action::USER_GRANT_CREATED).is_empty());
    }

    /// The wiring check: every write variant has a route that sends it, and the
    /// route's Tier A row lands with the change. One pass through all of them,
    /// read back through a second connection.
    #[tokio::test]
    async fn every_identity_route_sends_its_write_and_records_its_action() {
        use crate::audit::action::*;
        let l = lane();
        let (id, secret) = new_principal(&l, "edge").await; // InsertPrincipal (+ tenant)
        call(
            &l,
            "POST",
            "/admin/tenants",
            Some(serde_json::json!({"tenant": "solo"})),
        )
        .await; // InsertTenant
        let (_, added) = call(&l, "POST", &format!("/admin/principals/{id}/secrets"), None).await; // AddPrincipalSecret
        let secret_id = added["secret_id"].as_str().unwrap().to_owned();
        call(
            &l,
            "DELETE",
            &format!("/admin/principals/{id}/secrets/{secret_id}"),
            None,
        )
        .await; // RevokePrincipalSecret
        call(&l, "DELETE", &format!("/admin/principals/{id}"), None).await; // RevokePrincipal
        call(&l, "DELETE", "/admin/tenants/solo", None).await; // DisableTenant
        call(
            &l,
            "POST",
            "/admin/user-grants",
            Some(serde_json::json!({"sub": "alice", "tenant": "acme", "roles": ["viewer"]})),
        )
        .await; // InsertUserGrant
        call(&l, "DELETE", "/admin/user-grants/alice/acme", None).await; // RevokeUserGrant

        let conn = fresh(&l);
        let rows = repo::list_audit(
            &conn,
            &repo::AuditQuery {
                limit: 100,
                ..repo::AuditQuery::default()
            },
        )
        .unwrap();
        let mut seen: Vec<(String, Option<String>, Option<String>)> = rows
            .iter()
            .filter(|r| {
                [
                    TENANT_CREATED,
                    TENANT_DISABLED,
                    PRINCIPAL_CREATED,
                    PRINCIPAL_REVOKED,
                    PRINCIPAL_SECRET_ADDED,
                    PRINCIPAL_SECRET_REVOKED,
                    USER_GRANT_CREATED,
                    USER_GRANT_REVOKED,
                ]
                .contains(&r.row.action.as_str())
            })
            .map(|r| {
                assert_eq!(r.row.outcome, "success", "{}", r.row.action);
                assert_eq!(r.row.actor_kind, "admin");
                assert_eq!(r.row.actor_id.as_deref(), Some(ADMIN_ACTOR));
                (
                    r.row.action.clone(),
                    r.row.key_id.clone(),
                    r.row.subject.clone(),
                )
            })
            .collect();
        seen.sort();
        let mut want = vec![
            (PRINCIPAL_CREATED.to_owned(), Some(id.clone()), None),
            (PRINCIPAL_REVOKED.to_owned(), Some(id.clone()), None),
            (PRINCIPAL_SECRET_ADDED.to_owned(), Some(id.clone()), None),
            (PRINCIPAL_SECRET_REVOKED.to_owned(), Some(id.clone()), None),
            (TENANT_CREATED.to_owned(), Some("solo".to_owned()), None),
            (TENANT_DISABLED.to_owned(), Some("solo".to_owned()), None),
            (
                USER_GRANT_CREATED.to_owned(),
                None,
                Some("alice".to_owned()),
            ),
            (
                USER_GRANT_REVOKED.to_owned(),
                None,
                Some("alice".to_owned()),
            ),
        ];
        want.sort();
        assert_eq!(seen, want);

        // INV-12: nothing in the record is the secret, the added secret or a
        // hash of either.
        let all = format!("{rows:?}");
        for s in [&secret, added["secret"].as_str().unwrap()] {
            assert!(!all.contains(s));
            let hex: String = hash_secret(s).iter().map(|b| format!("{b:02x}")).collect();
            assert!(!all.contains(&hex));
        }
    }

    /// Atomicity, from the audit side: when the transaction fails, the audit row
    /// goes with the change instead of surviving it.
    #[tokio::test]
    async fn an_identity_change_and_its_audit_row_commit_or_fail_together() {
        let l = lane();
        let (id, _) = new_principal(&l, "edge").await;
        let sink = crate::audit::AuditSink::new(
            l._writer.handle(),
            crate::telemetry::Metrics::new(),
            crate::audit::AuditConfig::default(),
        );
        let (_, stored) = mint_for_test();
        let clash = crate::store::writer::AdminWrite::InsertPrincipal {
            principal: repo::NewPrincipal {
                principal_id: id, // the primary key is already taken: a hard SQL error
                tenant_id: "acme".to_owned(),
                name: "someone-else".to_owned(),
                kind: "node".to_owned(),
                scopes: vec!["s".to_owned()],
                indexes: vec!["*".to_owned()],
                audience: "logless".to_owned(),
                max_ttl_secs: 60,
                created_by: None,
                secret: stored,
            },
            now: T0,
        };
        let row = sink.transactional(
            Event::new(
                crate::audit::action::PRINCIPAL_CREATED,
                Outcome::Success,
                ActorKind::Admin,
                T0,
            )
            .key_id("sp_clash"),
        );
        assert!(l
            ._writer
            .handle()
            .write_admin_audited(clash, Some(row))
            .is_err());

        let rows = audit_rows(&l, crate::audit::action::PRINCIPAL_CREATED);
        assert_eq!(rows.len(), 1, "only the real creation is on record");
        assert_eq!(repo::list_principals(&fresh(&l), None).unwrap().len(), 1);
        assert!(rows[0].row.key_id.as_deref() != Some("sp_clash"));
    }

    fn mint_for_test() -> (String, repo::NewSecret) {
        super::identity::mint_secret(T0, None)
    }

    /// A principal secret is not a key to either neighbouring lane.
    #[tokio::test]
    async fn a_principal_secret_opens_neither_the_admin_lane_nor_internal_token() {
        use crate::session::{CustodyId, Sid};
        let l = lane();
        let (_, secret) = new_principal(&l, "edge").await;
        assert!(resolves(&l, &secret).is_some(), "it is a live secret");

        for (method, uri) in ALL_ROUTES {
            let response = l
                .router
                .clone()
                .oneshot(req(method, uri, Some(&secret), None))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );
        }

        // /internal/token over the same store, with a real session behind it,
        // so the key is the only thing standing in the way.
        let sessions = Arc::new(SessionMap::new(SessionPolicy::default()));
        let issued = sessions.create(
            Sid("sid-1".to_owned()),
            CustodyId("cust-1".to_owned()),
            "alice".to_owned(),
            T0,
        );
        let (_, backend) = call(
            &l,
            "POST",
            "/admin/api-keys",
            Some(serde_json::json!({"name": "backend"})),
        )
        .await;
        let internal = crate::http::internal::router(crate::http::internal::InternalState {
            sessions,
            reader: Arc::new(Reader::new(fresh(&l))),
            clock: Arc::new(l.clock.clone()),
            api_key: Some(Arc::from("bootstrap-backend-key-out-of-band")),
            writer: None,
            last_touch: Default::default(),
            metrics: crate::telemetry::Metrics::new(),
            audit: None,
            rate_limit: None,
        });
        let exchange = |key: String| {
            let request = Request::builder()
                .method("POST")
                .uri("/internal/token")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::from(
                    serde_json::json!({"session_token": issued.token.expose_for_cookie()})
                        .to_string(),
                ))
                .unwrap();
            let internal = internal.clone();
            async move {
                let response = internal.oneshot(request).await.unwrap();
                (response.status(), json(response).await)
            }
        };
        let (status, body) = exchange(secret).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("bad_api_key"))
        );
        // Control: a real backend key gets past the key check on this very request.
        let (_, body) = exchange(backend["secret"].as_str().unwrap().to_owned()).await;
        assert_ne!(body["error"], "bad_api_key");
    }

    /// Backend keys are not admin keys: not the issued kind either.
    #[tokio::test]
    async fn an_issued_backend_key_is_refused_on_every_route() {
        let l = lane();
        let (_, backend) = call(
            &l,
            "POST",
            "/admin/api-keys",
            Some(serde_json::json!({"name": "backend"})),
        )
        .await;
        let key = backend["secret"].as_str().unwrap().to_owned();
        for (method, uri) in ALL_ROUTES {
            let response = l
                .router
                .clone()
                .oneshot(req(method, uri, Some(&key), None))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );
        }
        assert!(repo::list_tenants(&fresh(&l)).unwrap().len() == 1);
        assert!(repo::list_principals(&fresh(&l), None).unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_signing_key_list_follows_the_clock() {
        let l = lane();
        let states = |body: &serde_json::Value| -> Vec<String> {
            body.as_array()
                .unwrap()
                .iter()
                .map(|k| k["state"].as_str().unwrap().to_owned())
                .collect()
        };
        let (status, first) = call(&l, "GET", "/admin/signing-keys", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(states(&first), ["signing"]);
        assert_eq!(first[0]["x"].as_str().unwrap().len(), 43);
        assert!(first[0].get("seed").is_none() && first[0].get("seed_sealed").is_none());

        call(&l, "POST", "/admin/signing-keys/rotate", None).await;
        let (_, body) = call(&l, "GET", "/admin/signing-keys", None).await;
        assert_eq!(states(&body), ["pending", "signing"]);

        l.clock.set(T0.plus_secs(86_400));
        let (_, body) = call(&l, "GET", "/admin/signing-keys", None).await;
        assert_eq!(states(&body), ["signing", "published"]);

        l.clock.set(T0.plus_secs(2 * 86_400 + 300));
        let (_, body) = call(&l, "GET", "/admin/signing-keys", None).await;
        assert_eq!(states(&body), ["signing", "retired"]);
        assert_eq!(body[1]["kid"], first[0]["kid"]);
    }

    /// Unconfigured means off, not open.
    #[tokio::test]
    async fn an_unconfigured_admin_lane_is_closed() {
        let (router, _w) = harness(None);
        let response = router
            .oneshot(req("GET", "/admin/api-keys", Some(ADMIN_KEY), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
