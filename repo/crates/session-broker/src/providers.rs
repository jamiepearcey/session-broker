//! The identity providers this broker logs people in through (ADR-0018).
//!
//! One [`ProviderRegistry`] replaces the single `OidcClient` built at boot. It
//! holds every provider the store knows about, plus the config-file provider as
//! the read-only id `default`, and is what `/auth/*`, the keepalive worker and
//! the admin lane all read. A change installs a new immutable map, so a request
//! in flight keeps the client it started with.
//!
//! Clients connect lazily, except `default`, whose discovery at boot stays the
//! fail-fast check it always was. A store provider whose IdP is down at boot
//! costs that provider's logins, retried on the next attempt, and nothing else.
//!
//! The client secret is held in a [`ClientSecret`] and nowhere else: its `Debug`
//! is redacted and [`DiscoveryFailure`] is built from discovery only, which never
//! sends it. No response, log line or audit row carries it (INV-12).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use openidconnect::url::{Host, Url};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use crate::config::{ClientSecret, OidcConfig};
use crate::oauth::{OauthError, OidcClient, TxnStore, DEFAULT_PROVIDER};
use crate::store::repo::ProviderRow;

#[cfg(test)]
mod tests;

/// Discovery documents and key sets are small. A response past this is not one.
const MAX_DISCOVERY_BYTES: usize = 1024 * 1024;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// A named reason a provider cannot be used. `failure` is a stable word the
/// console branches on; `detail` is for the operator to read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{failure}: {detail}")]
pub struct DiscoveryFailure {
    pub failure: &'static str,
    pub detail: String,
}

fn fail(failure: &'static str, detail: impl Into<String>) -> DiscoveryFailure {
    DiscoveryFailure {
        failure,
        detail: detail.into(),
    }
}

/// What a discovery document promised.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredEndpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub jwks_keys: usize,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// https, or plain http to this machine. Credentials are sent to whatever is
/// here, so nothing else is acceptable.
fn check_transport(raw: &str, url: &Url) -> Result<(), DiscoveryFailure> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(url) => Ok(()),
        _ => Err(fail(
            "issuer_not_https",
            format!("{raw} must be https, or http on loopback"),
        )),
    }
}

/// The form of an issuer URL, with no network involved.
pub fn check_issuer_url(issuer: &str) -> Result<(), DiscoveryFailure> {
    let url = Url::parse(issuer).map_err(|e| fail("invalid_url", e.to_string()))?;
    if url.host().is_none() {
        return Err(fail("invalid_url", "an issuer needs a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(fail("invalid_url", "an issuer carries no credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(fail(
            "invalid_url",
            "an issuer has no query or fragment (OIDC Discovery 1.0)",
        ));
    }
    check_transport(issuer, &url)
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    unreachable: &'static str,
    status: &'static str,
    malformed: &'static str,
) -> Result<T, DiscoveryFailure> {
    let mut response = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| fail(unreachable, e.without_url().to_string()))?;
    if !response.status().is_success() {
        return Err(fail(
            status,
            format!("{url} answered {}", response.status()),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| fail(unreachable, e.without_url().to_string()))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_DISCOVERY_BYTES {
            return Err(fail(malformed, format!("{url} answered too much")));
        }
    }
    serde_json::from_slice(&body).map_err(|e| {
        fail(
            malformed,
            format!("{url} did not answer the expected JSON: {e}"),
        )
    })
}

/// Discovery, and only discovery: no client id or secret is involved. Follows no
/// redirect. The returned `issuer` must equal the configured one byte for byte,
/// trailing slash included (OIDC Discovery 1.0 §4.3).
pub async fn probe_issuer(issuer: &str) -> Result<DiscoveredEndpoints, DiscoveryFailure> {
    check_issuer_url(issuer)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(DISCOVERY_TIMEOUT)
        .build()
        .map_err(|e| fail("unreachable", e.to_string()))?;

    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let doc: DiscoveryDocument =
        fetch_json(&http, &url, "unreachable", "http_status", "not_json").await?;

    let found = doc
        .issuer
        .ok_or_else(|| fail("missing_endpoint", "the document has no issuer"))?;
    if found != issuer {
        return Err(fail(
            "issuer_mismatch",
            format!("configured {issuer}, the document says {found}"),
        ));
    }

    let required = |value: Option<String>, name: &str| {
        let value = value.ok_or_else(|| fail("missing_endpoint", format!("no {name}")))?;
        let parsed = Url::parse(&value)
            .map_err(|e| fail("missing_endpoint", format!("{name} is not a URL: {e}")))?;
        check_transport(&value, &parsed)
            .map_err(|_| fail("insecure_endpoint", format!("{name} is {value}")))?;
        Ok::<String, DiscoveryFailure>(value)
    };
    let authorization_endpoint = required(doc.authorization_endpoint, "authorization_endpoint")?;
    let token_endpoint = required(doc.token_endpoint, "token_endpoint")?;
    let jwks_uri = required(doc.jwks_uri, "jwks_uri")?;

    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<serde_json::Value>,
    }
    let jwks: Jwks = fetch_json(
        &http,
        &jwks_uri,
        "jwks_unreachable",
        "jwks_unreachable",
        "jwks_invalid",
    )
    .await?;
    if jwks.keys.is_empty() {
        return Err(fail("jwks_invalid", "the key set is empty"));
    }

    Ok(DiscoveredEndpoints {
        issuer: found,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        userinfo_endpoint: doc.userinfo_endpoint,
        end_session_endpoint: doc.end_session_endpoint,
        jwks_keys: jwks.keys.len(),
    })
}

/// A provider's settings as the registry holds them.
#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub id: String,
    pub preset: String,
    pub display_name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<ClientSecret>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    /// A tombstone: listed nowhere, renews nothing, and its id stays taken.
    pub deleted: bool,
    /// The config-file provider.
    pub read_only: bool,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

impl From<ProviderRow> for ProviderSettings {
    fn from(row: ProviderRow) -> ProviderSettings {
        ProviderSettings {
            id: row.id,
            preset: row.preset,
            display_name: row.display_name,
            issuer_url: row.issuer_url,
            client_id: row.client_id,
            client_secret: row.client_secret,
            scopes: row.scopes,
            enabled: row.enabled,
            deleted: row.deleted_at.is_some(),
            read_only: false,
            created_at: Some(row.created_at.secs()),
            updated_at: Some(row.updated_at.secs()),
        }
    }
}

struct Entry {
    settings: ProviderSettings,
    client: OnceCell<Arc<OidcClient>>,
}

/// Why `/auth/login` will not start a login.
#[derive(Debug)]
pub enum LoginRefusal {
    NoProviders,
    Required,
    Unknown,
    Disabled,
    Unavailable(DiscoveryFailure),
}

/// What the keepalive worker gets for a grant's provider.
pub enum RefreshClient {
    Ready(Arc<OidcClient>),
    /// Deleted, so this grant can never be renewed.
    Gone,
    /// Cannot be reached or built right now. Retry.
    Unavailable(String),
}

type Entries = BTreeMap<String, Arc<Entry>>;

pub struct ProviderRegistry {
    redirect_uri: String,
    txns: Arc<TxnStore>,
    entries: RwLock<Arc<Entries>>,
}

impl ProviderRegistry {
    /// No providers at all.
    pub fn empty(redirect_uri: &str) -> ProviderRegistry {
        ProviderRegistry {
            redirect_uri: redirect_uri.to_owned(),
            txns: Arc::default(),
            entries: RwLock::new(Arc::default()),
        }
    }

    /// What the process starts from: the config provider if one is configured,
    /// discovered now, and every row of the store, connected on first use.
    pub async fn boot(
        config: &OidcConfig,
        rows: Vec<ProviderRow>,
        redirect_uri: String,
    ) -> Result<ProviderRegistry, OauthError> {
        let registry = ProviderRegistry::empty(&redirect_uri);
        for row in rows {
            registry.install(row.into(), None);
        }
        if let Some(issuer) = config.issuer_url.as_deref() {
            let client_id = config
                .client_id
                .as_deref()
                .ok_or(OauthError::NotConfigured)?;
            let secret = config
                .client_secret
                .as_ref()
                .ok_or(OauthError::NotConfigured)?;
            let client = OidcClient::build(
                issuer,
                client_id,
                secret.expose(),
                &redirect_uri,
                &config.scopes,
                DEFAULT_PROVIDER,
                registry.txns.clone(),
            )
            .await?;
            registry.install(
                ProviderSettings {
                    id: DEFAULT_PROVIDER.to_owned(),
                    preset: "config".to_owned(),
                    display_name: "Default".to_owned(),
                    issuer_url: issuer.to_owned(),
                    client_id: client_id.to_owned(),
                    client_secret: Some(secret.clone()),
                    scopes: config.scopes.clone(),
                    enabled: true,
                    deleted: false,
                    read_only: true,
                    created_at: None,
                    updated_at: None,
                },
                Some(Arc::new(client)),
            );
        }
        Ok(registry)
    }

    /// A registry around one already-built client, as the `default` provider.
    #[cfg(test)]
    pub(crate) fn with_default_client(client: OidcClient, redirect_uri: &str) -> ProviderRegistry {
        let registry = ProviderRegistry {
            redirect_uri: redirect_uri.to_owned(),
            txns: client.txn_store(),
            entries: RwLock::new(Arc::default()),
        };
        registry.install(
            ProviderSettings {
                id: DEFAULT_PROVIDER.to_owned(),
                preset: "config".to_owned(),
                display_name: "Default".to_owned(),
                issuer_url: client.issuer().to_owned(),
                client_id: String::new(),
                client_secret: None,
                scopes: Vec::new(),
                enabled: true,
                deleted: false,
                read_only: true,
                created_at: None,
                updated_at: None,
            },
            Some(Arc::new(client)),
        );
        registry
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    fn snapshot(&self) -> Arc<Entries> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Swap one provider in. A login in flight keeps working: the transaction
    /// store is shared and outlives any client.
    pub fn install(&self, settings: ProviderSettings, client: Option<Arc<OidcClient>>) {
        let mut guard = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let mut next = Entries::clone(&guard);
        next.insert(
            settings.id.clone(),
            Arc::new(Entry {
                settings,
                client: OnceCell::new_with(client),
            }),
        );
        *guard = Arc::new(next);
    }

    /// The live providers, tombstones excluded, in id order.
    pub fn list(&self) -> Vec<ProviderSettings> {
        self.snapshot()
            .values()
            .filter(|e| !e.settings.deleted)
            .map(|e| e.settings.clone())
            .collect()
    }

    /// One provider's settings, tombstones included.
    pub fn settings(&self, id: &str) -> Option<ProviderSettings> {
        self.snapshot().get(id).map(|e| e.settings.clone())
    }

    /// The client already connected for a provider, if any.
    pub fn connected_client(&self, id: &str) -> Option<Arc<OidcClient>> {
        self.snapshot()
            .get(id)
            .and_then(|e| e.client.get().cloned())
    }

    /// `(id, display_name)` of every provider that can start a login.
    pub fn enabled(&self) -> Vec<(String, String)> {
        self.snapshot()
            .values()
            .filter(|e| e.settings.enabled && !e.settings.deleted)
            .map(|e| (e.settings.id.clone(), e.settings.display_name.clone()))
            .collect()
    }

    /// Discover a provider and build its client. Discovery failures come back
    /// named; the secret takes no part in any of them.
    pub async fn connect(
        &self,
        settings: &ProviderSettings,
    ) -> Result<Arc<OidcClient>, DiscoveryFailure> {
        let secret = settings.client_secret.as_ref().ok_or_else(|| {
            fail(
                "secret_unavailable",
                "the stored client secret could not be opened; set it again",
            )
        })?;
        probe_issuer(&settings.issuer_url).await?;
        let client = OidcClient::build(
            &settings.issuer_url,
            &settings.client_id,
            secret.expose(),
            &self.redirect_uri,
            &settings.scopes,
            &settings.id,
            self.txns.clone(),
        )
        .await
        .map_err(|e| fail("client_build_failed", e.to_string()))?;
        Ok(Arc::new(client))
    }

    async fn client_of(&self, entry: &Entry) -> Result<Arc<OidcClient>, DiscoveryFailure> {
        entry
            .client
            .get_or_try_init(|| self.connect(&entry.settings))
            .await
            .cloned()
    }

    /// The client `/auth/login` starts on. Only an enabled provider qualifies.
    pub async fn client_for_login(
        &self,
        requested: Option<&str>,
    ) -> Result<Arc<OidcClient>, LoginRefusal> {
        let snapshot = self.snapshot();
        let entry = match requested {
            Some(id) => {
                let entry = snapshot
                    .get(id)
                    .filter(|e| !e.settings.deleted)
                    .ok_or(LoginRefusal::Unknown)?;
                if !entry.settings.enabled {
                    return Err(LoginRefusal::Disabled);
                }
                entry
            }
            None => {
                let mut enabled = snapshot
                    .values()
                    .filter(|e| e.settings.enabled && !e.settings.deleted);
                match (enabled.next(), enabled.next()) {
                    (None, _) => return Err(LoginRefusal::NoProviders),
                    (Some(only), None) => only,
                    _ => return Err(LoginRefusal::Required),
                }
            }
        };
        self.client_of(entry)
            .await
            .map_err(LoginRefusal::Unavailable)
    }

    /// The provider a presented login transaction belongs to.
    pub fn txn_provider(&self, txn_id: &str) -> Option<String> {
        self.txns.provider_of(txn_id)
    }

    pub fn discard_txn(&self, txn_id: &str) {
        self.txns.discard(txn_id);
    }

    /// The client a callback completes on. Disabling a provider also stops the
    /// logins already in flight on it: an operator who disables one because it is
    /// compromised does not want one more session from it.
    pub async fn client_for_callback(
        &self,
        provider_id: &str,
    ) -> Result<Arc<OidcClient>, OauthError> {
        let snapshot = self.snapshot();
        let entry = snapshot
            .get(provider_id)
            .filter(|e| !e.settings.deleted)
            .ok_or(OauthError::ProviderGone)?;
        if !entry.settings.enabled {
            return Err(OauthError::ProviderDisabled);
        }
        self.client_of(entry)
            .await
            .map_err(|e| OauthError::ProviderUnavailable(e.to_string()))
    }

    /// The client that renews a grant: the provider that issued it, enabled or
    /// not. A missing `default` is a config change that may be undone, so it is
    /// retried; a missing or deleted store provider is final.
    pub async fn client_for_refresh(&self, provider_id: &str) -> RefreshClient {
        let snapshot = self.snapshot();
        match snapshot.get(provider_id) {
            None if provider_id == DEFAULT_PROVIDER => {
                RefreshClient::Unavailable("the config-file provider is not configured".to_owned())
            }
            None => RefreshClient::Gone,
            Some(entry) if entry.settings.deleted => RefreshClient::Gone,
            Some(entry) => match self.client_of(entry).await {
                Ok(client) => RefreshClient::Ready(client),
                Err(e) => RefreshClient::Unavailable(e.to_string()),
            },
        }
    }

    /// Would a config-provider subject be mistaken for another provider's person?
    /// True when the part before the first `|` names any provider, tombstones
    /// included, because a tombstone's grants still exist.
    pub fn subject_collides(&self, sub: &str) -> bool {
        sub.split_once('|').is_some_and(|(prefix, _)| {
            prefix != DEFAULT_PROVIDER && self.snapshot().contains_key(prefix)
        })
    }
}
