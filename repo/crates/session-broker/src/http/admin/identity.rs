//! `/admin/tenants`, `/admin/principals`, `/admin/user-grants` and the
//! read-only `/admin/signing-keys` — the token issuer's identities as data.
//!
//! Same lane and the same guard as the rest of `/admin/*` (the admin key, never
//! a backend key). Every mutation is Tier A: its audit row commits in the same
//! transaction, and a store failure refuses the change.
//!
//! ## Secrets
//!
//! A principal secret is `sbp_` plus 32 random bytes, base64url. It is shown
//! once, in the response that creates it, and only its SHA-256 (of the whole
//! string, prefix included) is stored. It has **no expiry** unless the operator
//! asks for one. Adding a secret leaves the older ones valid: rotation is "add,
//! swap the config, revoke the old one", and nothing forces the last step.
//! `expire_old_in_secs` is there for operators who would rather the old one
//! stopped on a date.
//!
//! ## Tenants
//!
//! Nobody has to create a tenant. Naming one in a principal or a grant creates
//! it, in the same transaction. A disabled tenant refuses new principals and
//! grants and its principals stop resolving; it is not re-enabled by being named
//! again.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{authorised, hash_secret, refuse, short_id, AdminState, ADMIN_ACTOR};
use crate::audit::{action, ActorKind, Event, Outcome};
use crate::clock::Timestamp;
use crate::http::guards::PeerAddr;
use crate::store::repo;
use crate::store::writer::AdminWrite;

const DEFAULT_TENANT: &str = "default";
const DEFAULT_MAX_TTL_SECS: u64 = 30 * 86_400;
/// The longest a principal may be allowed to mint tokens for.
const MAX_MAX_TTL_SECS: u64 = 365 * 86_400;
/// A secret expiry further out than this is a typo, not a plan.
const MAX_SECRET_LIFE_SECS: u64 = 10 * 365 * 86_400;
/// Stops a principal minting a token too big to be worth carrying.
const MAX_LIST_ITEMS: usize = 64;
const KINDS: [&str; 5] = ["ingest", "node", "replica", "reader", "admin"];

// --- shared helpers -----------------------------------------------------

fn bad(error: &'static str, detail: &'static str) -> Response {
    refuse(StatusCode::BAD_REQUEST, error, detail)
}

fn store_failed(what: &'static str, e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "admin: {what}");
    refuse(
        StatusCode::INTERNAL_SERVER_ERROR,
        "store_error",
        "The store could not be read or written.",
    )
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, Box<Response>> {
    serde_json::from_slice(body).map_err(|_| {
        Box::new(bad(
            "bad_request",
            "The body must be a JSON object with the documented fields and no others.",
        ))
    })
}

/// A body that may be absent altogether.
fn parse_optional<T: DeserializeOwned + Default>(body: &Bytes) -> Result<T, Box<Response>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        Ok(T::default())
    } else {
        parse(body)
    }
}

/// `^[a-z0-9][a-z0-9-]{0,62}$`.
fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A short word with nothing in it that would need quoting: names, scopes,
/// indexes, roles, audiences.
fn is_word(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Validate and de-duplicate a list of words, keeping the first occurrence's
/// position. `None` if it is empty, too long, or holds a bad item.
fn clean_list(items: Vec<String>) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !is_word(&item) {
            return None;
        }
        if !out.contains(&item) {
            out.push(item);
        }
    }
    (!out.is_empty() && out.len() <= MAX_LIST_ITEMS).then_some(out)
}

fn tenant_or_default(tenant: Option<String>) -> Result<String, Box<Response>> {
    let tenant = tenant.unwrap_or_else(|| DEFAULT_TENANT.to_owned());
    if is_slug(&tenant) {
        Ok(tenant)
    } else {
        Err(Box::new(bad(
            "invalid_tenant",
            "A tenant is lower-case letters, digits and hyphens, starting with a letter or digit, at most 63 characters.",
        )))
    }
}

fn admin_event(action: &str, now: Timestamp) -> Event {
    Event::new(action, Outcome::Success, ActorKind::Admin, now).actor_id(ADMIN_ACTOR)
}

/// Run one mutation with its Tier A row in the same transaction. `Ok(false)` is
/// "nothing to act on" (or, for a create, "already there").
fn apply(state: &AdminState, write: AdminWrite, event: Event) -> Result<bool, Box<Response>> {
    let audit_row = state.audit.as_ref().map(|sink| sink.transactional(event));
    state
        .writer
        .write_admin_audited(write, audit_row)
        .map_err(|e| {
            // The transaction carried both, so neither happened (INV-13).
            if let Some(sink) = &state.audit {
                sink.note_transactional_failure();
            }
            Box::new(store_failed("an identity change failed", e))
        })
}

/// A fresh secret: the plaintext to hand over once, and the row to store.
pub(super) fn mint_secret(
    now: Timestamp,
    expires_in_secs: Option<u64>,
) -> (String, repo::NewSecret) {
    let secret = format!("sbp_{}", crate::oauth::random_id());
    let stored = repo::NewSecret {
        secret_id: format!("sps_{}", short_id()),
        hash: hash_secret(&secret),
        expires_at: expires_in_secs.map(|secs| now.plus_secs(secs)),
    };
    (secret, stored)
}

fn check_secret_life(secs: Option<u64>) -> Result<(), Box<Response>> {
    match secs {
        Some(0) | None => Ok(()),
        Some(s) if s <= MAX_SECRET_LIFE_SECS => Ok(()),
        Some(_) => Err(Box::new(bad(
            "expiry_out_of_range",
            "An expiry may be at most 10 years away.",
        ))),
    }
}

/// What a created or added secret looks like in a response. The only place the
/// plaintext ever appears.
#[derive(Debug, Serialize)]
struct IssuedSecret {
    secret_id: String,
    /// Shown exactly once. Not recoverable.
    secret: String,
    created_at: i64,
    expires_at: Option<i64>,
}

fn issued(secret: String, stored: &repo::NewSecret, now: Timestamp) -> IssuedSecret {
    IssuedSecret {
        secret_id: stored.secret_id.clone(),
        secret,
        created_at: now.secs(),
        expires_at: stored.expires_at.map(Timestamp::secs),
    }
}

// --- tenants ------------------------------------------------------------

#[derive(Debug, Serialize)]
struct TenantView {
    tenant: String,
    display_name: Option<String>,
    created_at: i64,
    disabled_at: Option<i64>,
    live: bool,
}

impl From<repo::TenantRow> for TenantView {
    fn from(r: repo::TenantRow) -> TenantView {
        TenantView {
            tenant: r.tenant_id,
            display_name: r.display_name,
            created_at: r.created_at.secs(),
            live: r.disabled_at.is_none(),
            disabled_at: r.disabled_at.map(Timestamp::secs),
        }
    }
}

pub(super) async fn list_tenants(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    match state.reader.with(repo::list_tenants) {
        Ok(rows) => {
            Json(rows.into_iter().map(TenantView::from).collect::<Vec<_>>()).into_response()
        }
        Err(e) => store_failed("listing tenants failed", e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTenantRequest {
    tenant: String,
    display_name: Option<String>,
}

pub(super) async fn create_tenant(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: CreateTenantRequest = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let tenant = match tenant_or_default(Some(request.tenant)) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let display_name = request.display_name.map(|n| n.trim().to_owned());
    if display_name
        .as_deref()
        .is_some_and(|n| n.is_empty() || n.len() > 128 || n.chars().any(char::is_control))
    {
        return bad(
            "invalid_display_name",
            "A display name is 1 to 128 characters with no control characters.",
        );
    }

    let now = state.clock.now();
    let event = admin_event(action::TENANT_CREATED, now).key_id(tenant.clone());
    match apply(
        &state,
        AdminWrite::InsertTenant {
            tenant_id: tenant.clone(),
            display_name: display_name.clone(),
            now,
        },
        event,
    ) {
        Ok(true) => {
            tracing::info!(tenant = %tenant, "admin: tenant created");
            (
                StatusCode::CREATED,
                Json(TenantView {
                    tenant,
                    display_name,
                    created_at: now.secs(),
                    disabled_at: None,
                    live: true,
                }),
            )
                .into_response()
        }
        Ok(false) => refuse(
            StatusCode::CONFLICT,
            "tenant_exists",
            "That tenant already exists.",
        ),
        Err(response) => *response,
    }
}

pub(super) async fn disable_tenant(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let event = admin_event(action::TENANT_DISABLED, now).key_id(tenant.clone());
    match apply(
        &state,
        AdminWrite::DisableTenant {
            tenant_id: tenant.clone(),
            now,
        },
        event,
    ) {
        Ok(true) => {
            tracing::info!(tenant = %tenant, "admin: tenant disabled");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_tenant",
            "No enabled tenant with that name.",
        ),
        Err(response) => *response,
    }
}

// --- principals ---------------------------------------------------------

#[derive(Debug, Serialize)]
struct PrincipalView {
    principal_id: String,
    tenant: String,
    name: String,
    kind: String,
    scopes: Vec<String>,
    indexes: Vec<String>,
    audience: String,
    max_ttl_secs: u64,
    created_at: i64,
    created_by: Option<String>,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
    live: bool,
}

impl From<repo::PrincipalRow> for PrincipalView {
    fn from(r: repo::PrincipalRow) -> PrincipalView {
        PrincipalView {
            principal_id: r.principal_id,
            tenant: r.tenant_id,
            name: r.name,
            kind: r.kind,
            scopes: r.scopes,
            indexes: r.indexes,
            audience: r.audience,
            max_ttl_secs: r.max_ttl_secs,
            created_at: r.created_at.secs(),
            created_by: r.created_by,
            last_used_at: r.last_used_at.map(Timestamp::secs),
            live: r.revoked_at.is_none(),
            revoked_at: r.revoked_at.map(Timestamp::secs),
        }
    }
}

#[derive(Debug, Serialize)]
struct SecretView {
    secret_id: String,
    created_at: i64,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
    /// Derived with the same rule the token lane resolves by.
    live: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct TenantFilter {
    tenant: Option<String>,
}

pub(super) async fn list_principals(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Query(filter): Query<TenantFilter>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    match state
        .reader
        .with(|conn| repo::list_principals(conn, filter.tenant.as_deref()))
    {
        Ok(rows) => Json(
            rows.into_iter()
                .map(PrincipalView::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => store_failed("listing principals failed", e),
    }
}

#[derive(Debug, Serialize)]
struct PrincipalDetail {
    #[serde(flatten)]
    principal: PrincipalView,
    secrets: Vec<SecretView>,
}

pub(super) async fn get_principal(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let found = state.reader.with(|conn| {
        let Some(principal) = repo::get_principal(conn, &principal_id)? else {
            return Ok(None);
        };
        let secrets = repo::list_principal_secrets(conn, &principal_id)?;
        Ok::<_, repo::RepoError>(Some((principal, secrets)))
    });
    match found {
        Ok(Some((principal, secrets))) => Json(PrincipalDetail {
            principal: principal.into(),
            secrets: secrets
                .into_iter()
                .map(|s| SecretView {
                    live: s.live_at(now),
                    secret_id: s.secret_id,
                    created_at: s.created_at.secs(),
                    expires_at: s.expires_at.map(Timestamp::secs),
                    revoked_at: s.revoked_at.map(Timestamp::secs),
                })
                .collect(),
        })
        .into_response(),
        Ok(None) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_principal",
            "No principal with that id.",
        ),
        Err(e) => store_failed("reading a principal failed", e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePrincipalRequest {
    name: String,
    /// Defaults to `default`. Created if nobody has used it yet.
    tenant: Option<String>,
    kind: String,
    /// What the principal may do. The broker stamps these into tokens and does
    /// not interpret them.
    scopes: Vec<String>,
    /// Defaults to `["*"]`: every index of the tenant.
    indexes: Option<Vec<String>>,
    audience: String,
    /// Longest token lifetime it may ask for. Defaults to 30 days, at most 365.
    max_ttl_secs: Option<u64>,
    /// When the first secret stops working. Default: never.
    expires_in_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CreatedPrincipal {
    #[serde(flatten)]
    principal: PrincipalView,
    secret: IssuedSecret,
}

pub(super) async fn create_principal(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: CreatePrincipalRequest = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let tenant = match tenant_or_default(request.tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let name = request.name.trim().to_owned();
    if !is_word(&name) {
        return bad(
            "invalid_name",
            "A name is 1 to 128 characters with no spaces or control characters.",
        );
    }
    if !KINDS.contains(&request.kind.as_str()) {
        return bad(
            "invalid_kind",
            "kind must be one of ingest, node, replica, reader, admin.",
        );
    }
    let Some(scopes) = clean_list(request.scopes) else {
        return bad(
            "invalid_scopes",
            "scopes must be 1 to 64 distinct words with no spaces.",
        );
    };
    let indexes = match request.indexes {
        None => vec!["*".to_owned()],
        Some(indexes) => match clean_list(indexes) {
            Some(indexes) => indexes,
            None => {
                return bad(
                    "invalid_indexes",
                    "indexes must be 1 to 64 distinct words with no spaces; [\"*\"] means all.",
                )
            }
        },
    };
    if !is_word(&request.audience) {
        return bad(
            "invalid_audience",
            "An audience is 1 to 128 characters with no spaces or control characters.",
        );
    }
    let max_ttl_secs = request.max_ttl_secs.unwrap_or(DEFAULT_MAX_TTL_SECS);
    if !(1..=MAX_MAX_TTL_SECS).contains(&max_ttl_secs) {
        return bad(
            "max_ttl_out_of_range",
            "max_ttl_secs must be between 1 second and 365 days.",
        );
    }
    if request.expires_in_secs == Some(0) {
        return bad(
            "expiry_out_of_range",
            "expires_in_secs must be at least 1; leave it out for a secret that does not expire.",
        );
    }
    if let Err(response) = check_secret_life(request.expires_in_secs) {
        return *response;
    }

    let now = state.clock.now();
    let principal_id = format!("sp_{}", short_id());
    let (secret, stored) = mint_secret(now, request.expires_in_secs);
    let issued_secret = issued(secret, &stored, now);
    let event = admin_event(action::PRINCIPAL_CREATED, now)
        .key_id(principal_id.clone())
        .detail(serde_json::json!({
            "tenant": tenant,
            "name": name,
            "kind": request.kind,
            "audience": request.audience,
            "secret_id": stored.secret_id,
            "secret_expires_at": stored.expires_at.map(Timestamp::secs),
        }));
    let view = PrincipalView {
        principal_id: principal_id.clone(),
        tenant: tenant.clone(),
        name: name.clone(),
        kind: request.kind.clone(),
        scopes: scopes.clone(),
        indexes: indexes.clone(),
        audience: request.audience.clone(),
        max_ttl_secs,
        created_at: now.secs(),
        created_by: Some(ADMIN_ACTOR.to_owned()),
        last_used_at: None,
        revoked_at: None,
        live: true,
    };
    let created = apply(
        &state,
        AdminWrite::InsertPrincipal {
            principal: repo::NewPrincipal {
                principal_id: principal_id.clone(),
                tenant_id: tenant.clone(),
                name,
                kind: request.kind,
                scopes,
                indexes,
                audience: request.audience,
                max_ttl_secs,
                created_by: Some(ADMIN_ACTOR.to_owned()),
                secret: stored,
            },
            now,
        },
        event,
    );
    match created {
        Ok(true) => {
            tracing::info!(principal_id = %principal_id, tenant = %tenant, "admin: principal created");
            (
                StatusCode::CREATED,
                Json(CreatedPrincipal {
                    principal: view,
                    secret: issued_secret,
                }),
            )
                .into_response()
        }
        Ok(false) => {
            let disabled = state
                .reader
                .with(|conn| repo::tenant_is_disabled(conn, &tenant))
                .unwrap_or(false);
            if disabled {
                refuse(
                    StatusCode::CONFLICT,
                    "tenant_disabled",
                    "That tenant is disabled, so it takes no new principals.",
                )
            } else {
                refuse(
                    StatusCode::CONFLICT,
                    "principal_exists",
                    "The tenant already has a principal with that name (a revoked one keeps its name).",
                )
            }
        }
        Err(response) => *response,
    }
}

pub(super) async fn revoke_principal(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let event = admin_event(action::PRINCIPAL_REVOKED, now).key_id(principal_id.clone());
    match apply(
        &state,
        AdminWrite::RevokePrincipal {
            principal_id: principal_id.clone(),
            now,
        },
        event,
    ) {
        Ok(true) => {
            tracing::info!(principal_id = %principal_id, "admin: principal revoked");
            StatusCode::NO_CONTENT.into_response()
        }
        // "Revoked" and "there was nothing to revoke" must not look alike.
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_principal",
            "No live principal with that id.",
        ),
        Err(response) => *response,
    }
}

// --- principal secrets --------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddSecretRequest {
    /// When the new secret stops working. Default: never.
    expires_in_secs: Option<u64>,
    /// Date the principal's older live secrets this many seconds from now (`0`:
    /// now). Default: leave them valid until they are revoked. A secret already
    /// due to stop sooner keeps its earlier date.
    expire_old_in_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AddedSecret {
    principal_id: String,
    #[serde(flatten)]
    secret: IssuedSecret,
    /// When the older secrets stop working, if the request asked for that.
    old_secrets_expire_at: Option<i64>,
}

pub(super) async fn add_secret(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: AddSecretRequest = match parse_optional(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.expires_in_secs == Some(0) {
        return bad(
            "expiry_out_of_range",
            "expires_in_secs must be at least 1; leave it out for a secret that does not expire.",
        );
    }
    for secs in [request.expires_in_secs, request.expire_old_in_secs] {
        if let Err(response) = check_secret_life(secs) {
            return *response;
        }
    }

    let now = state.clock.now();
    let (secret, stored) = mint_secret(now, request.expires_in_secs);
    let issued_secret = issued(secret, &stored, now);
    let expire_others_at = request.expire_old_in_secs.map(|s| now.plus_secs(s));
    let event = admin_event(action::PRINCIPAL_SECRET_ADDED, now)
        .key_id(principal_id.clone())
        .detail(serde_json::json!({
            "secret_id": stored.secret_id,
            "secret_expires_at": stored.expires_at.map(Timestamp::secs),
            "old_secrets_expire_at": expire_others_at.map(Timestamp::secs),
        }));
    match apply(
        &state,
        AdminWrite::AddPrincipalSecret {
            principal_id: principal_id.clone(),
            secret: stored,
            expire_others_at,
            now,
        },
        event,
    ) {
        Ok(true) => {
            tracing::info!(principal_id = %principal_id, secret_id = %issued_secret.secret_id, "admin: principal secret added");
            (
                StatusCode::CREATED,
                Json(AddedSecret {
                    principal_id,
                    secret: issued_secret,
                    old_secrets_expire_at: expire_others_at.map(Timestamp::secs),
                }),
            )
                .into_response()
        }
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_principal",
            "No live principal with that id.",
        ),
        Err(response) => *response,
    }
}

pub(super) async fn revoke_secret(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path((principal_id, secret_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let event = admin_event(action::PRINCIPAL_SECRET_REVOKED, now)
        .key_id(principal_id.clone())
        .detail(serde_json::json!({ "secret_id": secret_id }));
    match apply(
        &state,
        AdminWrite::RevokePrincipalSecret {
            principal_id: principal_id.clone(),
            secret_id: secret_id.clone(),
            now,
        },
        event,
    ) {
        Ok(true) => {
            tracing::info!(principal_id = %principal_id, secret_id = %secret_id, "admin: principal secret revoked");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_secret",
            "No live secret with that id on that principal.",
        ),
        Err(response) => *response,
    }
}

// --- user grants --------------------------------------------------------

#[derive(Debug, Serialize)]
struct UserGrantView {
    sub: String,
    tenant: String,
    roles: Vec<String>,
    indexes: Vec<String>,
    created_at: i64,
    created_by: Option<String>,
    revoked_at: Option<i64>,
    live: bool,
}

impl From<repo::UserGrantRow> for UserGrantView {
    fn from(r: repo::UserGrantRow) -> UserGrantView {
        UserGrantView {
            sub: r.sub,
            tenant: r.tenant_id,
            roles: r.roles,
            indexes: r.indexes,
            created_at: r.created_at.secs(),
            created_by: r.created_by,
            live: r.revoked_at.is_none(),
            revoked_at: r.revoked_at.map(Timestamp::secs),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct GrantFilter {
    tenant: Option<String>,
    sub: Option<String>,
}

pub(super) async fn list_user_grants(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Query(filter): Query<GrantFilter>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    match state
        .reader
        .with(|conn| repo::list_user_grants(conn, filter.tenant.as_deref(), filter.sub.as_deref()))
    {
        Ok(rows) => Json(
            rows.into_iter()
                .map(UserGrantView::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => store_failed("listing user grants failed", e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGrantRequest {
    /// The identity provider's `sub` for the person.
    sub: String,
    /// Defaults to `default`. Created if nobody has used it yet.
    tenant: Option<String>,
    roles: Vec<String>,
    /// Defaults to `["*"]`.
    indexes: Option<Vec<String>>,
}

pub(super) async fn create_user_grant(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: CreateGrantRequest = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let tenant = match tenant_or_default(request.tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    if request.sub.is_empty()
        || request.sub.len() > 256
        || request.sub.chars().any(char::is_control)
    {
        return bad(
            "invalid_sub",
            "sub is 1 to 256 characters with no control characters.",
        );
    }
    let Some(roles) = clean_list(request.roles) else {
        return bad(
            "invalid_roles",
            "roles must be 1 to 64 distinct words with no spaces.",
        );
    };
    let indexes = match request.indexes {
        None => vec!["*".to_owned()],
        Some(indexes) => match clean_list(indexes) {
            Some(indexes) => indexes,
            None => {
                return bad(
                    "invalid_indexes",
                    "indexes must be 1 to 64 distinct words with no spaces; [\"*\"] means all.",
                )
            }
        },
    };

    let now = state.clock.now();
    let event = admin_event(action::USER_GRANT_CREATED, now)
        .subject(request.sub.clone())
        .detail(serde_json::json!({ "tenant": tenant, "roles": roles, "indexes": indexes }));
    let view = UserGrantView {
        sub: request.sub.clone(),
        tenant: tenant.clone(),
        roles: roles.clone(),
        indexes: indexes.clone(),
        created_at: now.secs(),
        created_by: Some(ADMIN_ACTOR.to_owned()),
        revoked_at: None,
        live: true,
    };
    let created = apply(
        &state,
        AdminWrite::InsertUserGrant {
            grant: repo::NewUserGrant {
                sub: request.sub,
                tenant_id: tenant.clone(),
                roles,
                indexes,
                created_by: Some(ADMIN_ACTOR.to_owned()),
            },
            now,
        },
        event,
    );
    match created {
        Ok(true) => {
            tracing::info!(tenant = %tenant, "admin: user grant created");
            (StatusCode::CREATED, Json(view)).into_response()
        }
        Ok(false) => {
            let disabled = state
                .reader
                .with(|conn| repo::tenant_is_disabled(conn, &tenant))
                .unwrap_or(false);
            if disabled {
                refuse(
                    StatusCode::CONFLICT,
                    "tenant_disabled",
                    "That tenant is disabled, so it takes no new grants.",
                )
            } else {
                refuse(
                    StatusCode::CONFLICT,
                    "grant_exists",
                    "That person already has a live grant on that tenant; revoke it to change it.",
                )
            }
        }
        Err(response) => *response,
    }
}

pub(super) async fn revoke_user_grant(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path((sub, tenant)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    let event = admin_event(action::USER_GRANT_REVOKED, now)
        .subject(sub.clone())
        .detail(serde_json::json!({ "tenant": tenant }));
    match apply(
        &state,
        AdminWrite::RevokeUserGrant {
            sub,
            tenant_id: tenant.clone(),
            now,
        },
        event,
    ) {
        Ok(true) => {
            tracing::info!(tenant = %tenant, "admin: user grant revoked");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => refuse(
            StatusCode::NOT_FOUND,
            "unknown_grant",
            "No live grant for that person on that tenant.",
        ),
        Err(response) => *response,
    }
}

// --- signing keys (read-only; rotation is in the parent module) ---------

#[derive(Debug, Serialize)]
struct SigningKeyView {
    kid: String,
    /// The public key, base64url, as published in the JWK Set. Never the seed.
    x: String,
    created_at: i64,
    activate_at: i64,
    retire_at: Option<i64>,
    removed_at: Option<i64>,
    /// `pending` (published, not signing yet), `signing` (what tokens are
    /// signed with now), `published` (older, still verifying), `retired`
    /// (past its end date, no longer published) or `removed`.
    state: &'static str,
}

pub(super) async fn list_signing_keys(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let now = state.clock.now();
    match state.reader.with(repo::list_signing_keys) {
        Ok(rows) => {
            // Newest first, so the first key that is live and has started is
            // the one signing.
            let mut signing_taken = false;
            let views: Vec<SigningKeyView> = rows
                .into_iter()
                .map(|r| {
                    let published = r.removed_at.is_none() && r.retire_at.is_none_or(|at| at > now);
                    let state = if r.removed_at.is_some() {
                        "removed"
                    } else if !published {
                        "retired"
                    } else if r.activate_at > now {
                        "pending"
                    } else if !signing_taken {
                        signing_taken = true;
                        "signing"
                    } else {
                        "published"
                    };
                    SigningKeyView {
                        x: URL_SAFE_NO_PAD.encode(r.public_key),
                        kid: r.kid,
                        created_at: r.created_at.secs(),
                        activate_at: r.activate_at.secs(),
                        retire_at: r.retire_at.map(Timestamp::secs),
                        removed_at: r.removed_at.map(Timestamp::secs),
                        state,
                    }
                })
                .collect();
            Json(views).into_response()
        }
        Err(e) => store_failed("listing signing keys failed", e),
    }
}
