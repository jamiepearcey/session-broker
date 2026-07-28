//! The OpenID Connect relying-party client: provider discovery, the login
//! transaction lifecycle (INV-3), authorization-code exchange, and ID-token
//! validation.
//!
//! Discovery, PKCE, and ID-token signature/claims verification are delegated
//! entirely to the `openidconnect` crate (backed by `oauth2`) — this module
//! never parses a JWT or compares a signature by hand. What it owns instead:
//! turning a `return_to` into a server-side transaction record, remembering
//! that record exactly long enough to redeem it once, and translating a
//! successful token response into the shape `http/auth.rs` needs to mint a
//! session.
//!
//! **Txn storage is in-memory, not the durable `txn` table `store::repo`
//! already has a schema for.** The architecture note in
//! `docs/architecture/implementation-strategy.md` §5 treats session/generation
//! state as memory-primary with a write-behind durable copy; a login
//! transaction is shorter-lived and lower-stakes than a session, so this
//! module takes the simpler side of that tradeoff outright: a [`DashMap`]
//! behind [`TxnStore`], nothing durable. The cost is that a broker restart
//! mid-login (between `/auth/login` and `/auth/callback`) loses the
//! in-flight transaction — the user's browser still holds a
//! `__Host-broker_txn` cookie pointing at a txn id the new process has never
//! heard of, so the callback fails closed (`OauthError::UnknownTxn`,
//! INV-3a's code path) and they simply retry the login. That is the entire
//! blast radius: no session is ever at risk, because a txn only ever gates
//! the *creation* of one, never an existing one. Wiring the durable `txn`
//! table for login continuity across restarts is future work, not required
//! by any invariant here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use dashmap::DashMap;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthType, AuthorizationCode, ClientId, ClientSecret as OidcClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    TokenResponse as OidcTokenResponse,
};
use rand::RngCore;

use crate::clock::Timestamp;
use crate::config::OidcConfig;

/// How long a login transaction may sit unredeemed before it is refused
/// (INV-3). Fixed, not read from config: the txn cookie's own `Max-Age`
/// (`http/auth.rs`) is built to match this exactly, so the two must move
/// together if this ever becomes configurable.
pub(crate) const TXN_TTL_SECS: u64 = 600;

/// The concrete type `CoreClient::from_provider_metadata(..).set_redirect_uri(..)`
/// produces: an authorization endpoint and a (per discovery, possibly-unset
/// in the type system even though discovery always supplies one) token
/// endpoint, nothing else. Spelled out because the type-state generics on
/// `Client` are otherwise unnameable at a struct field.
type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error(
        "OIDC is not configured: issuer_url, client_id, client_secret and redirect_uri are all required"
    )]
    NotConfigured,
    #[error("invalid OIDC issuer or redirect URL: {0}")]
    InvalidUrl(String),
    #[error("provider discovery failed: {0}")]
    Discovery(String),
    /// INV-3a / INV-3c: no txn cookie was presented, or the id it named has
    /// already been consumed (first touch or replay).
    #[error("no matching login transaction (missing, already used, or from a different process)")]
    UnknownTxn,
    /// INV-3d.
    #[error("login transaction has expired")]
    TxnExpired,
    /// INV-3b.
    #[error("state parameter does not match the transaction")]
    StateMismatch,
    /// The `?error=` callback form, or a callback missing `code`/`state`.
    #[error("the identity provider reported an error: {0}")]
    ProviderError(String),
    #[error("authorization code exchange failed: {0}")]
    Exchange(String),
    #[error("token response carried no id_token")]
    MissingIdToken,
    /// INV-3e lives here: `openidconnect`'s `IdToken::claims` verifies
    /// signature, issuer, audience, expiry, and nonce together, and this is
    /// the one error variant for all of them.
    #[error("id_token failed verification: {0}")]
    InvalidIdToken(String),
}

impl OauthError {
    /// A stable, low-cardinality code for the audit record and for metrics.
    ///
    /// Deliberately NOT `Display`: that carries provider strings and URLs,
    /// which are attacker-influenced and unbounded. The record wants "which
    /// check failed", and a `reason` column that can hold arbitrary provider
    /// text is a column nobody can group by.
    pub fn code(&self) -> &'static str {
        match self {
            OauthError::NotConfigured => "not_configured",
            OauthError::InvalidUrl(_) => "invalid_url",
            OauthError::Discovery(_) => "discovery_failed",
            OauthError::UnknownTxn => "unknown_txn",
            OauthError::TxnExpired => "txn_expired",
            OauthError::StateMismatch => "state_mismatch",
            OauthError::ProviderError(_) => "provider_error",
            OauthError::Exchange(_) => "exchange_failed",
            OauthError::MissingIdToken => "missing_id_token",
            OauthError::InvalidIdToken(_) => "invalid_id_token",
        }
    }
}

/// What a successful [`OidcClient::complete_login`] hands back: enough to
/// mint a session (`sub`) plus the upstream grant material for whichever
/// milestone wires durable custody storage (`store::` is out of scope for
/// this module). Nothing here is logged or persisted by M2 — the HTTP layer
/// reads `sub` and lets the rest drop.
pub struct UpstreamTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Timestamp,
    pub scope: Option<String>,
    pub sub: String,
}

impl std::fmt::Debug for UpstreamTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTokens")
            .field("access_token", &"redacted")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "redacted"),
            )
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .field("sub", &self.sub)
            .finish()
    }
}

/// A server-side login transaction record (INV-3): `state`, PKCE verifier,
/// `nonce`, and `return_to`, keyed by a random id the browser only ever
/// sees the opaque form of via [`Txn::cookie_value`].
struct TxnRecord {
    state: String,
    nonce: String,
    pkce_verifier: String,
    return_to: Option<String>,
    created_at: Timestamp,
}

/// Handed back by [`OidcClient::begin_login`]. The only thing a caller may
/// do with it is read the opaque id to put in the `__Host-broker_txn`
/// cookie — `state`/`nonce`/`pkce_verifier`/`return_to` never leave this
/// module, which is the substance of "the browser holds only a random txn
/// id" (INV-3).
pub struct Txn {
    id: String,
}

impl Txn {
    pub fn cookie_value(&self) -> &str {
        &self.id
    }
}

/// In-memory, single-use, TTL-bounded transaction store. See the module
/// docs for why this is memory-only rather than the durable `txn` table.
#[derive(Default)]
struct TxnStore {
    txns: DashMap<String, TxnRecord>,
}

impl TxnStore {
    fn insert(&self, record: TxnRecord) -> Txn {
        let id = random_id();
        self.txns.insert(id.clone(), record);
        Txn { id }
    }

    /// Single-use take (INV-3c): removed unconditionally on first lookup, so
    /// a replay of the same code+state — or a duplicate callback firing
    /// twice for the same navigation — finds nothing the second time.
    fn take(&self, id: &str) -> Option<TxnRecord> {
        self.txns.remove(id).map(|(_, record)| record)
    }
}

/// A discovered, ready-to-use OIDC relying-party client, built once at
/// startup from [`OidcConfig`] via provider discovery (§7 of the
/// implementation strategy). Send+Sync: the only mutable state is the txn
/// map, which is internally synchronized, so `Arc<OidcClient>` is the shape
/// the HTTP layer holds it in.
pub struct OidcClient {
    core: DiscoveredClient,
    http_client: reqwest::Client,
    scopes: Vec<Scope>,
    txns: TxnStore,
}

impl OidcClient {
    /// Discover the provider (`{issuer}/.well-known/openid-configuration`
    /// plus its JWKS) and build a client ready to drive the authorization
    /// code flow. Fails if any of `issuer_url` / `client_id` /
    /// `client_secret` / `redirect_uri` is missing — `BrokerConfig::load`
    /// already refuses an issuer without a secret at startup, but
    /// `redirect_uri` has no such guard today, so this is the backstop.
    pub async fn discover(config: &OidcConfig) -> Result<OidcClient, OauthError> {
        let issuer = config
            .issuer_url
            .as_deref()
            .ok_or(OauthError::NotConfigured)?;
        let client_id = config
            .client_id
            .as_deref()
            .ok_or(OauthError::NotConfigured)?;
        let client_secret = config
            .client_secret
            .as_ref()
            .ok_or(OauthError::NotConfigured)?
            .expose();
        let redirect_uri = config
            .redirect_uri
            .as_deref()
            .ok_or(OauthError::NotConfigured)?;

        Self::build(
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            &config.scopes,
        )
        .await
    }

    /// The shared construction path behind both [`OidcClient::discover`] and
    /// the crate-internal test helper below: everything from URL parsing
    /// onward is identical regardless of where the strings came from.
    async fn build(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        scopes: &[String],
    ) -> Result<OidcClient, OauthError> {
        let issuer_url =
            IssuerUrl::new(issuer.to_owned()).map_err(|e| OauthError::InvalidUrl(e.to_string()))?;
        let redirect_url = RedirectUrl::new(redirect_uri.to_owned())
            .map_err(|e| OauthError::InvalidUrl(e.to_string()))?;

        // SSRF hardening for the backend HTTP client that performs discovery
        // and code exchange: never follow a redirect. A malicious or
        // compromised issuer response redirecting these calls elsewhere
        // (e.g. an internal address) must not be silently followed.
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OauthError::Discovery(e.to_string()))?;

        let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|e| OauthError::Discovery(e.to_string()))?;

        let core = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client_id.to_owned()),
            Some(OidcClientSecret::new(client_secret.to_owned())),
        )
        .set_redirect_uri(redirect_url)
        // `mock-idp` (and plenty of real providers) only advertise
        // `client_secret_post` — the default is HTTP Basic auth, which
        // would silently send no usable `client_id` in the token request
        // body and fail with a generic `invalid_request`.
        .set_auth_type(AuthType::RequestBody);

        // `openid` is added automatically by `from_provider_metadata`
        // (`use_openid_scope` defaults to true); drop it from the
        // configured list so the authorize URL doesn't carry it twice.
        let scopes = scopes
            .iter()
            .filter(|s| s.as_str() != "openid")
            .map(|s| Scope::new(s.clone()))
            .collect();

        Ok(OidcClient {
            core,
            http_client,
            scopes,
            txns: TxnStore::default(),
        })
    }

    /// Test-only construction path from plain strings, so tests never need a
    /// `config::ClientSecret` (whose constructor is private to `config.rs`
    /// on purpose — it is only ever built from a config source string).
    #[cfg(test)]
    pub(crate) async fn discover_for_tests(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        scopes: &[&str],
    ) -> Result<OidcClient, OauthError> {
        let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
        Self::build(issuer, client_id, client_secret, redirect_uri, &scopes).await
    }

    /// Start a login: generate PKCE (S256), `state`, and `nonce`; store them
    /// server-side keyed by a fresh random txn id; return the URL to send
    /// the browser to and the txn handle for the caller to cookie.
    /// `return_to` is trusted as already-validated (INV-4 is the HTTP
    /// layer's job, via `guards::safe_return_to`, before this is called).
    pub fn begin_login(&self, return_to: Option<String>, now: Timestamp) -> (String, Txn) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut request = self
            .core
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);
        for scope in &self.scopes {
            request = request.add_scope(scope.clone());
        }
        let (authorize_url, csrf_token, nonce) = request.url();

        let txn = self.txns.insert(TxnRecord {
            state: csrf_token.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            return_to,
            created_at: now,
        });

        (authorize_url.to_string(), txn)
    }

    /// Abandon a presented txn without completing the exchange — the
    /// `?error=` callback form, or one missing `code`/`state`. Still a
    /// "touch" for INV-3's single-use guarantee: the id cannot be reused
    /// after this even though nothing was ever exchanged.
    pub fn discard_txn(&self, txn_id: &str) {
        self.txns.take(txn_id);
    }

    /// Redeem a callback: take the (single-use) txn, check `state`, check
    /// the TTL, exchange the code with the stored PKCE verifier, and
    /// validate the returned ID token's issuer/audience/expiry/nonce.
    /// Returns the extracted upstream grant plus the txn's stored
    /// `return_to`, since the txn record — the only place that value lives
    /// — is gone by the time this returns.
    pub async fn complete_login(
        &self,
        txn_id: &str,
        presented_state: &str,
        code: &str,
        now: Timestamp,
    ) -> Result<(UpstreamTokens, Option<String>), OauthError> {
        // INV-3c: taken unconditionally, before any of the checks below, so
        // every subsequent failure still leaves the txn consumed.
        let record = self.txns.take(txn_id).ok_or(OauthError::UnknownTxn)?;

        // INV-3d: TTL judged against the injected clock, never wall time —
        // deterministic under `TestClock::advance`, no sleeping required.
        if now.since(record.created_at) >= TXN_TTL_SECS {
            return Err(OauthError::TxnExpired);
        }
        // INV-3b.
        if record.state != presented_state {
            return Err(OauthError::StateMismatch);
        }

        let token_request = self
            .core
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|e| OauthError::Exchange(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(record.pkce_verifier));

        let token_response = token_request
            .request_async(&self.http_client)
            .await
            .map_err(|e| OauthError::Exchange(e.to_string()))?;

        let id_token = token_response
            .id_token()
            .ok_or(OauthError::MissingIdToken)?;
        let verifier = self.core.id_token_verifier();
        let nonce = Nonce::new(record.nonce);
        // INV-3e (plus iss/aud/exp): `claims()` verifies the signature and
        // every one of those together, and refuses to hand back a claims
        // reference unless all of them hold.
        let claims = id_token
            .claims(&verifier, &nonce)
            .map_err(|e| OauthError::InvalidIdToken(e.to_string()))?;

        let sub = claims.subject().as_str().to_owned();
        let access_token = token_response.access_token().secret().to_owned();
        let refresh_token = token_response
            .refresh_token()
            .map(|t| t.secret().to_owned());
        let expires_at = now.plus_secs(
            token_response
                .expires_in()
                .map(|d| d.as_secs())
                .unwrap_or(300),
        );
        let scope = token_response.scopes().map(|scopes| {
            scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });

        Ok((
            UpstreamTokens {
                access_token,
                refresh_token,
                expires_at,
                scope,
                sub,
            },
            record.return_to,
        ))
    }
}

impl OidcClient {
    /// Exchange a stored refresh token for a fresh grant (§6, the keepalive
    /// worker's only upstream call).
    ///
    /// Deliberately NOT reachable from the session hot path: INV-8 says a
    /// browser refresh never touches the IdP, and the way that invariant stays
    /// true is that the only caller of this is the background worker.
    ///
    /// `sub` is not re-derived here. A refresh-token grant is not required to
    /// return an `id_token`, so the subject stays whatever the original login
    /// established — the custody row already records it.
    pub async fn refresh_grant(
        &self,
        refresh_token: &str,
        now: Timestamp,
    ) -> Result<RefreshedGrant, RefreshGrantError> {
        let response = self
            .core
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
            .map_err(|e| RefreshGrantError::Transient(e.to_string()))?
            .request_async(&self.http_client)
            .await
            .map_err(classify_refresh_error)?;

        let lifetime_secs = response.expires_in().map(|d| d.as_secs()).unwrap_or(300);

        Ok(RefreshedGrant {
            access_token: response.access_token().secret().to_owned(),
            // Absent means the IdP does not rotate refresh tokens; the caller
            // keeps the one it already has. Both behaviours are in scope (§6).
            rotated_refresh_token: response.refresh_token().map(|t| t.secret().to_owned()),
            expires_at: now.plus_secs(lifetime_secs),
            lifetime_secs,
        })
    }
}

/// A successful upstream refresh.
pub struct RefreshedGrant {
    pub access_token: String,
    pub rotated_refresh_token: Option<String>,
    pub expires_at: Timestamp,
    pub lifetime_secs: u64,
}

impl std::fmt::Debug for RefreshedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshedGrant")
            .field("access_token", &"redacted")
            .field(
                "rotated_refresh_token",
                &self.rotated_refresh_token.as_ref().map(|_| "redacted"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why an upstream refresh failed, split the one way the scheduler cares
/// about: will retrying ever help?
#[derive(Debug, thiserror::Error)]
pub enum RefreshGrantError {
    /// Network, 5xx, or 429. Retry with backoff.
    #[error("upstream refresh failed transiently: {0}")]
    Transient(String),
    /// `invalid_grant` — the refresh token is revoked, expired, or already
    /// consumed. It will never work again, so retrying only wastes the
    /// schedule and delays propagating the revocation (ADR-0011).
    #[error("upstream refused the grant permanently: {0}")]
    Permanent(String),
}

/// `invalid_grant` is the one OAuth error code that means "stop trying".
/// Everything else — including a malformed response we cannot classify — is
/// treated as transient, because wrongly giving up kills every session behind
/// this custody under the default `kill` policy, while wrongly retrying costs
/// only a scheduled attempt.
fn classify_refresh_error<E: std::error::Error + 'static>(
    error: openidconnect::RequestTokenError<
        E,
        openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    >,
) -> RefreshGrantError {
    use openidconnect::core::CoreErrorResponseType;
    use openidconnect::RequestTokenError;

    match &error {
        RequestTokenError::ServerResponse(response)
            if *response.error() == CoreErrorResponseType::InvalidGrant =>
        {
            RefreshGrantError::Permanent(error.to_string())
        }
        _ => RefreshGrantError::Transient(error.to_string()),
    }
}

/// A fresh random identifier: 32 CSPRNG bytes, base64url-encoded. Used for
/// txn ids here, and reused by `http/auth.rs` for the `Sid`/`CustodyId` a
/// successful callback mints — not a secret in the `SessionToken` sense (it
/// never authenticates anything by itself), just unpredictable enough that
/// nobody can guess another user's in-flight txn or a future session id.
pub(crate) fn random_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock_idp::{spawn_mock_idp, MockIdpConfig};

    const CLIENT_ID: &str = "session-broker-dev";
    const CLIENT_SECRET: &str = "dev-secret";
    const REDIRECT_URI: &str = "http://localhost:8080/auth/callback";

    async fn client_against(handle: &mock_idp::MockIdpHandle) -> OidcClient {
        OidcClient::discover_for_tests(
            handle.base_url(),
            CLIENT_ID,
            CLIENT_SECRET,
            REDIRECT_URI,
            &["openid", "offline_access"],
        )
        .await
        .expect("discovery against a freshly spawned mock IdP must succeed")
    }

    fn query_param(url: &str, name: &str) -> String {
        openidconnect::url::Url::parse(url)
            .expect("a valid URL")
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| panic!("missing query param {name:?} in {url}"))
    }

    /// Follow a real (network) redirect chain against the spawned mock IdP:
    /// GET the authorize URL `begin_login` produced, and pull the `code`
    /// it hands back out of the `Location` header — the same technique
    /// `mock-idp`'s own test suite uses, without needing anything listening
    /// on `REDIRECT_URI`.
    async fn authorize_and_get_code(authorize_url: &str) -> String {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client.get(authorize_url).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        query_param(&location, "code")
    }

    #[tokio::test]
    async fn happy_path_yields_the_subject_and_the_stored_return_to() {
        let handle = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
        let oidc = client_against(&handle).await;
        let now = Timestamp(1_700_000_000);

        let (authorize_url, txn) = oidc.begin_login(Some("/dashboard".to_owned()), now);
        let state = query_param(&authorize_url, "state");
        let code = authorize_and_get_code(&authorize_url).await;

        let (tokens, return_to) = oidc
            .complete_login(txn.cookie_value(), &state, &code, now)
            .await
            .expect("a well-formed callback must succeed");

        assert_eq!(tokens.sub, "user-1");
        assert_eq!(return_to.as_deref(), Some("/dashboard"));

        handle.shutdown().await;
    }

    // --- INV-3b: state mismatch -------------------------------------------

    #[tokio::test]
    async fn a_state_that_does_not_match_the_transaction_is_rejected() {
        let handle = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
        let oidc = client_against(&handle).await;
        let now = Timestamp(1_700_000_000);

        let (authorize_url, txn) = oidc.begin_login(None, now);
        let code = authorize_and_get_code(&authorize_url).await;

        let result = oidc
            .complete_login(txn.cookie_value(), "not-the-real-state", &code, now)
            .await;
        assert!(matches!(result, Err(OauthError::StateMismatch)));

        handle.shutdown().await;
    }

    // --- INV-3c: single use -------------------------------------------------

    #[tokio::test]
    async fn a_txn_can_be_consumed_exactly_once() {
        let handle = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
        let oidc = client_against(&handle).await;
        let now = Timestamp(1_700_000_000);

        let (authorize_url, txn) = oidc.begin_login(None, now);
        let state = query_param(&authorize_url, "state");
        let code = authorize_and_get_code(&authorize_url).await;

        let first = oidc
            .complete_login(txn.cookie_value(), &state, &code, now)
            .await;
        assert!(first.is_ok(), "first redemption must succeed");

        let replay = oidc
            .complete_login(txn.cookie_value(), &state, &code, now)
            .await;
        assert!(
            matches!(replay, Err(OauthError::UnknownTxn)),
            "replaying the same txn id must find nothing: {replay:?}"
        );

        handle.shutdown().await;
    }

    // --- INV-3d: expiry, deterministic ---------------------------------------

    #[tokio::test]
    async fn a_txn_past_its_ttl_is_rejected_without_sleeping() {
        let handle = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
        let oidc = client_against(&handle).await;
        let start = Timestamp(1_700_000_000);

        let (authorize_url, txn) = oidc.begin_login(None, start);
        let state = query_param(&authorize_url, "state");
        let code = authorize_and_get_code(&authorize_url).await;

        // Exactly at the boundary and beyond: `since` uses `>=`, so this is
        // the first instant the txn must be refused.
        let past_ttl = start.plus_secs(TXN_TTL_SECS);
        let result = oidc
            .complete_login(txn.cookie_value(), &state, &code, past_ttl)
            .await;
        assert!(matches!(result, Err(OauthError::TxnExpired)));

        handle.shutdown().await;
    }

    // --- INV-3e: nonce ---------------------------------------------------------

    #[tokio::test]
    async fn an_id_token_whose_nonce_does_not_match_the_transaction_is_rejected() {
        // The mock IdP always echoes back exactly the `nonce` it was given
        // at `/authorize`, so a normal round trip through this client can
        // never produce a mismatch by itself. To prove the check actually
        // fires, drive `/authorize` directly (bypassing `begin_login`) with
        // the SAME `code_challenge` our txn already has a verifier for, but
        // a DIFFERENT `nonce` — PKCE still lines up (so the exchange
        // succeeds and a real, validly-signed id_token comes back), but that
        // id_token's `nonce` claim is the forged one, not the txn's.
        let handle = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
        let oidc = client_against(&handle).await;
        let now = Timestamp(1_700_000_000);

        let (authorize_url, txn) = oidc.begin_login(None, now);
        let state = query_param(&authorize_url, "state");
        let code_challenge = query_param(&authorize_url, "code_challenge");

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let forged = client
            .get(format!("{}/authorize", handle.base_url()))
            .query(&[
                ("response_type", "code"),
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT_URI),
                ("scope", "openid"),
                ("state", &state),
                ("nonce", "a-nonce-the-txn-never-stored"),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(forged.status(), reqwest::StatusCode::FOUND);
        let location = forged
            .headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let forged_code = query_param(&location, "code");

        let result = oidc
            .complete_login(txn.cookie_value(), &state, &forged_code, now)
            .await;
        assert!(
            matches!(result, Err(OauthError::InvalidIdToken(_))),
            "a nonce mismatch must fail id_token verification: {result:?}"
        );

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn an_unknown_txn_id_is_rejected() {
        let handle = spawn_mock_idp(MockIdpConfig::default()).await.unwrap();
        let oidc = client_against(&handle).await;
        let now = Timestamp(1_700_000_000);

        let result = oidc
            .complete_login("no-such-txn-id", "state", "code", now)
            .await;
        assert!(matches!(result, Err(OauthError::UnknownTxn)));

        handle.shutdown().await;
    }
}
