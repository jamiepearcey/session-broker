//! `/admin/providers` — identity providers as data (ADR-0018).
//!
//! Same lane, same guard, same Tier A rule as the rest of `/admin/*`: the audit
//! row commits in the mutation's transaction, and a store failure refuses it.
//!
//! The client secret is write-only. [`ProviderView`] has no field that could
//! carry it, the audit detail records only whether it changed, and the request
//! types have no `Debug`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::identity::{admin_event, apply, bad, clean_list, is_slug, parse, store_failed};
use super::{authorised, refuse, AdminState};
use crate::audit::action;
use crate::config::ClientSecret;
use crate::http::guards::PeerAddr;
use crate::oauth::DEFAULT_PROVIDER;
use crate::providers::{check_issuer_url, probe_issuer, DiscoveryFailure, ProviderSettings};
use crate::store::repo;
use crate::store::writer::AdminWrite;

const PRESETS: [&str; 6] = ["entra", "okta", "auth0", "google", "keycloak", "generic"];
/// `default` is the config-file provider and `test` would shadow the test route.
const RESERVED_IDS: [&str; 2] = [DEFAULT_PROVIDER, "test"];
const DEFAULT_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];
const MAX_PEOPLE: i64 = 256;

#[derive(Debug, Serialize)]
struct ProviderView {
    id: String,
    preset: String,
    display_name: String,
    issuer_url: String,
    client_id: String,
    scopes: Vec<String>,
    enabled: bool,
    read_only: bool,
    has_secret: bool,
    redirect_uri: String,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

fn view(state: &AdminState, s: ProviderSettings) -> ProviderView {
    ProviderView {
        has_secret: s.client_secret.is_some(),
        id: s.id,
        preset: s.preset,
        display_name: s.display_name,
        issuer_url: s.issuer_url,
        client_id: s.client_id,
        scopes: s.scopes,
        enabled: s.enabled,
        read_only: s.read_only,
        redirect_uri: state.providers.redirect_uri().to_owned(),
        created_at: s.created_at,
        updated_at: s.updated_at,
    }
}

#[derive(Serialize)]
struct DiscoveryRefusal {
    error: &'static str,
    failure: &'static str,
    detail: String,
}

fn discovery_refused(failure: DiscoveryFailure) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(DiscoveryRefusal {
            error: "discovery_failed",
            failure: failure.failure,
            detail: failure.detail,
        }),
    )
        .into_response()
}

fn check_issuer(issuer: &str) -> Result<(), Box<Response>> {
    check_issuer_url(issuer).map_err(|failure| {
        Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(DiscoveryRefusal {
                    error: "invalid_issuer",
                    failure: failure.failure,
                    detail: failure.detail,
                }),
            )
                .into_response(),
        )
    })
}

fn check_preset(preset: &str) -> Result<(), Box<Response>> {
    if PRESETS.contains(&preset) {
        Ok(())
    } else {
        Err(Box::new(bad(
            "invalid_preset",
            "preset is one of entra, okta, auth0, google, keycloak, generic.",
        )))
    }
}

fn check_display_name(name: &str) -> Result<(), Box<Response>> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(Box::new(bad(
            "invalid_display_name",
            "display_name is 1 to 128 characters with no control characters.",
        )));
    }
    Ok(())
}

fn check_client_id(client_id: &str) -> Result<(), Box<Response>> {
    if client_id.is_empty() || client_id.len() > 512 || client_id.chars().any(char::is_control) {
        return Err(Box::new(bad(
            "invalid_client_id",
            "client_id is 1 to 512 characters with no control characters.",
        )));
    }
    Ok(())
}

fn check_secret(secret: &str) -> Result<ClientSecret, Box<Response>> {
    if secret.is_empty() || secret.len() > 4096 || secret.chars().any(char::is_control) {
        return Err(Box::new(bad(
            "invalid_secret",
            "client_secret is 1 to 4096 characters with no control characters. To keep the stored one, leave the field out.",
        )));
    }
    Ok(ClientSecret::new(secret.to_owned()))
}

fn check_scopes(scopes: Vec<String>) -> Result<Vec<String>, Box<Response>> {
    match clean_list(scopes) {
        Some(scopes) if scopes.iter().any(|s| s == "openid") => Ok(scopes),
        _ => Err(Box::new(bad(
            "invalid_scopes",
            "scopes must be 1 to 64 distinct words with no spaces, and must include openid.",
        ))),
    }
}

fn unknown() -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        "unknown_provider",
        "No provider has that id.",
    )
}

fn read_only() -> Response {
    refuse(
        StatusCode::CONFLICT,
        "read_only_provider",
        "The default provider comes from the config file and cannot be changed here.",
    )
}

fn namespace_in_use(state: &AdminState, id: &str) -> Result<bool, Box<Response>> {
    state
        .reader
        .with(|conn| repo::provider_namespace_in_use(conn, id))
        .map_err(|e| Box::new(store_failed("reading a provider's people failed", e)))
}

/// The audit detail. It says whether the secret changed and nothing else about it.
fn detail(s: &ProviderSettings, secret_changed: bool) -> serde_json::Value {
    serde_json::json!({
        "provider": s.id,
        "preset": s.preset,
        "issuer_url": s.issuer_url,
        "client_id": s.client_id,
        "scopes": s.scopes,
        "enabled": s.enabled,
        "secret_changed": secret_changed,
    })
}

#[derive(Serialize)]
struct ProviderList {
    redirect_uri: String,
    providers: Vec<ProviderView>,
}

pub(super) async fn list(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let providers = state
        .providers
        .list()
        .into_iter()
        .map(|s| view(&state, s))
        .collect();
    Json(ProviderList {
        redirect_uri: state.providers.redirect_uri().to_owned(),
        providers,
    })
    .into_response()
}

pub(super) async fn get_one(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    match state.providers.settings(&id).filter(|s| !s.deleted) {
        Some(settings) => Json(view(&state, settings)).into_response(),
        None => unknown(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    id: String,
    preset: String,
    display_name: String,
    issuer_url: String,
    client_id: String,
    client_secret: String,
    scopes: Option<Vec<String>>,
    enabled: Option<bool>,
}

pub(super) async fn create(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: CreateRequest = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match create_inner(&state, request).await {
        Ok(response) | Err(response) => response,
    }
}

async fn create_inner(state: &AdminState, request: CreateRequest) -> Result<Response, Response> {
    let id = request.id;
    if !is_slug(&id) {
        return Err(bad(
            "invalid_id",
            "An id is lower-case letters, digits and hyphens, starting with a letter or digit, at most 63 characters.",
        ));
    }
    if RESERVED_IDS.contains(&id.as_str()) {
        return Err(refuse(
            StatusCode::CONFLICT,
            "reserved_id",
            "default and test are reserved ids.",
        ));
    }
    check_preset(&request.preset).map_err(|r| *r)?;
    check_display_name(&request.display_name).map_err(|r| *r)?;
    check_issuer(&request.issuer_url).map_err(|r| *r)?;
    check_client_id(&request.client_id).map_err(|r| *r)?;
    let secret = check_secret(&request.client_secret).map_err(|r| *r)?;
    let scopes = match request.scopes {
        Some(scopes) => check_scopes(scopes).map_err(|r| *r)?,
        None => DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
    };

    // An id is a set of people. It may come back on the issuer it had, and it may
    // not start meaning a different one, or their grants would go with it.
    let retired = refuse(
        StatusCode::CONFLICT,
        "provider_id_retired",
        "People or grants already exist under this id for another issuer. Choose another id.",
    );
    match state.providers.settings(&id) {
        Some(existing) if !existing.deleted => {
            return Err(refuse(
                StatusCode::CONFLICT,
                "provider_exists",
                "A provider already has this id.",
            ))
        }
        Some(tombstone) => {
            if tombstone.issuer_url != request.issuer_url {
                return Err(retired);
            }
        }
        None => {
            if namespace_in_use(state, &id).map_err(|r| *r)? {
                return Err(retired);
            }
        }
    }

    let now = state.clock.now();
    let mut settings = ProviderSettings {
        id: id.clone(),
        preset: request.preset,
        display_name: request.display_name,
        issuer_url: request.issuer_url,
        client_id: request.client_id,
        client_secret: Some(secret.clone()),
        scopes,
        enabled: request.enabled.unwrap_or(true),
        deleted: false,
        read_only: false,
        created_at: Some(now.secs()),
        updated_at: Some(now.secs()),
    };
    let client = if settings.enabled {
        Some(
            state
                .providers
                .connect(&settings)
                .await
                .map_err(discovery_refused)?,
        )
    } else {
        None
    };

    let event = admin_event(action::PROVIDER_CREATED, now).detail(detail(&settings, true));
    let write = AdminWrite::InsertProvider {
        provider: repo::NewProvider {
            id,
            preset: settings.preset.clone(),
            display_name: settings.display_name.clone(),
            issuer_url: settings.issuer_url.clone(),
            client_id: settings.client_id.clone(),
            client_secret: secret,
            scopes: settings.scopes.clone(),
            enabled: settings.enabled,
        },
        now,
    };
    if !apply(state, write, event).map_err(|r| *r)? {
        return Err(refuse(
            StatusCode::CONFLICT,
            "provider_exists",
            "A provider already has this id.",
        ));
    }
    settings.updated_at = Some(now.secs());
    tracing::info!(provider = %settings.id, "admin: provider created");
    state.providers.install(settings.clone(), client);
    Ok((StatusCode::CREATED, Json(view(state, settings))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    preset: Option<String>,
    display_name: Option<String>,
    issuer_url: Option<String>,
    client_id: Option<String>,
    /// Absent: the stored secret stays.
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    enabled: Option<bool>,
}

pub(super) async fn update(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: UpdateRequest = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match update_inner(&state, id, request).await {
        Ok(response) | Err(response) => response,
    }
}

async fn update_inner(
    state: &AdminState,
    id: String,
    request: UpdateRequest,
) -> Result<Response, Response> {
    let Some(current) = state.providers.settings(&id).filter(|s| !s.deleted) else {
        return Err(unknown());
    };
    if current.read_only {
        return Err(read_only());
    }

    let mut next = current.clone();
    if let Some(preset) = request.preset {
        check_preset(&preset).map_err(|r| *r)?;
        next.preset = preset;
    }
    if let Some(name) = request.display_name {
        check_display_name(&name).map_err(|r| *r)?;
        next.display_name = name;
    }
    if let Some(issuer) = request.issuer_url {
        check_issuer(&issuer).map_err(|r| *r)?;
        next.issuer_url = issuer;
    }
    if let Some(client_id) = request.client_id {
        check_client_id(&client_id).map_err(|r| *r)?;
        next.client_id = client_id;
    }
    let new_secret = match request.client_secret {
        Some(secret) => Some(check_secret(&secret).map_err(|r| *r)?),
        None => None,
    };
    if let Some(secret) = &new_secret {
        next.client_secret = Some(secret.clone());
    }
    if let Some(scopes) = request.scopes {
        next.scopes = check_scopes(scopes).map_err(|r| *r)?;
    }
    if let Some(enabled) = request.enabled {
        next.enabled = enabled;
    }

    if next.issuer_url != current.issuer_url && namespace_in_use(state, &id).map_err(|r| *r)? {
        return Err(refuse(
            StatusCode::CONFLICT,
            "issuer_locked",
            "People or grants already exist under this provider, and they belong to its issuer. Add a new provider for the other issuer.",
        ));
    }

    let connection_changed = next.issuer_url != current.issuer_url
        || next.client_id != current.client_id
        || next.client_secret != current.client_secret
        || next.scopes != current.scopes;
    // Re-enabling discovers afresh: the keys it holds may be long out of date. A
    // rename while the IdP is down has nothing to prove, so it does not probe.
    let reusable = !connection_changed && current.enabled;
    let client = if next.enabled && !reusable {
        Some(
            state
                .providers
                .connect(&next)
                .await
                .map_err(discovery_refused)?,
        )
    } else if reusable {
        state.providers.connected_client(&id)
    } else {
        None
    };

    let now = state.clock.now();
    next.updated_at = Some(now.secs());
    let event =
        admin_event(action::PROVIDER_UPDATED, now).detail(detail(&next, new_secret.is_some()));
    let write = AdminWrite::UpdateProvider {
        provider: repo::ProviderUpdate {
            id,
            preset: next.preset.clone(),
            display_name: next.display_name.clone(),
            issuer_url: next.issuer_url.clone(),
            client_id: next.client_id.clone(),
            client_secret: new_secret,
            scopes: next.scopes.clone(),
            enabled: next.enabled,
        },
        now,
    };
    if !apply(state, write, event).map_err(|r| *r)? {
        return Err(unknown());
    }
    tracing::info!(provider = %next.id, enabled = next.enabled, "admin: provider updated");
    state.providers.install(next.clone(), client);
    Ok(Json(view(state, next)).into_response())
}

pub(super) async fn remove(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let Some(mut settings) = state.providers.settings(&id).filter(|s| !s.deleted) else {
        return unknown();
    };
    if settings.read_only {
        return read_only();
    }
    let now = state.clock.now();
    let event = admin_event(action::PROVIDER_DELETED, now).detail(detail(&settings, false));
    match apply(&state, AdminWrite::DeleteProvider { id, now }, event) {
        Ok(true) => {
            tracing::info!(provider = %settings.id, "admin: provider deleted");
            settings.deleted = true;
            settings.enabled = false;
            settings.client_secret = None;
            state.providers.install(settings, None);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => unknown(),
        Err(response) => *response,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestRequest {
    issuer_url: String,
}

#[derive(Serialize)]
struct TestFound {
    ok: bool,
    issuer_url: String,
    #[serde(flatten)]
    endpoints: crate::providers::DiscoveredEndpoints,
}

#[derive(Serialize)]
struct TestFailed {
    ok: bool,
    issuer_url: String,
    failure: &'static str,
    detail: String,
}

/// Discovery against an unsaved issuer. A failed probe is a successful request
/// with a named answer, so it is a 200.
pub(super) async fn test(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    let request: TestRequest = match parse(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let issuer_url = request.issuer_url;
    match probe_issuer(&issuer_url).await {
        Ok(endpoints) => Json(TestFound {
            ok: true,
            issuer_url,
            endpoints,
        })
        .into_response(),
        Err(failure) => Json(TestFailed {
            ok: false,
            issuer_url,
            failure: failure.failure,
            detail: failure.detail,
        })
        .into_response(),
    }
}

#[derive(Serialize)]
struct PersonView {
    sub: String,
    last_seen: i64,
    custodies: i64,
}

#[derive(Serialize)]
struct PeopleView {
    provider_id: String,
    people: Vec<PersonView>,
}

pub(super) async fn people(
    State(state): State<AdminState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = authorised(&state, &headers, peer.as_ref()) {
        return *response;
    }
    if state.providers.settings(&id).is_none_or(|s| s.deleted) {
        return unknown();
    }
    match state
        .reader
        .with(|conn| repo::provider_people(conn, &id, MAX_PEOPLE))
    {
        Ok(rows) => Json(PeopleView {
            provider_id: id,
            people: rows
                .into_iter()
                .map(|p| PersonView {
                    sub: p.sub,
                    last_seen: p.last_seen.secs(),
                    custodies: p.custodies,
                })
                .collect(),
        })
        .into_response(),
        Err(e) => store_failed("listing a provider's people failed", e),
    }
}
