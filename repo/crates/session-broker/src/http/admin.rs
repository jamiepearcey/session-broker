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
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::audit::{ActorKind, AuditSink, Event, Outcome};
use crate::clock::Clock;
use crate::session::SessionMap;
use crate::store::{repo, writer::WriterHandle, Reader};
use crate::telemetry::{LogControl, Metrics};

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
fn authorised(state: &AdminState, headers: &HeaderMap) -> Result<(), Box<Response>> {
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
        _ => Err(Box::new(refuse(
            StatusCode::UNAUTHORIZED,
            "unauthorised",
            "A valid admin API key is required.",
        ))),
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

async fn list_keys(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
    headers: HeaderMap,
    Json(request): Json<CreateKeyRequest>,
) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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

async fn list_sessions(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<AuditParams>,
) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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

async fn get_observability(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
    headers: HeaderMap,
    Json(request): Json<LogLevelRequest>,
) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
async fn restore_log_level(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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

async fn list_custody(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorised(&state, &headers) {
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
        for (method, uri) in [
            ("GET", "/admin/api-keys"),
            ("GET", "/admin/sessions"),
            ("GET", "/admin/custody"),
        ] {
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
