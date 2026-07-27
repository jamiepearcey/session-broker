//! Startup configuration: the plain [`MockIdpConfig`] that both the binary
//! and library callers build, plus the `clap`-derived CLI/env surface the
//! binary parses it from.

use std::net::SocketAddr;

use clap::Parser;

/// One registered OAuth client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub client_id: String,
    /// `None` models a public client: `/token` skips the `client_secret`
    /// check entirely for it.
    pub client_secret: Option<String>,
    /// Exact-match allow-list; `/authorize` rejects anything not in here.
    pub redirect_uris: Vec<String>,
}

/// One canned user `/authorize?login_as=<subject>` can select.
#[derive(Debug, Clone)]
pub struct UserConfig {
    pub subject: String,
    pub email: String,
    pub name: String,
}

/// Everything [`crate::spawn_mock_idp`] needs to start a server.
///
/// `Default` gives the single-client, single-user dev setup described in
/// the crate docs, bound to an ephemeral port — the shape integration tests
/// want. The binary instead builds this from [`Cli`], which pins a fixed
/// port so `cargo run -p mock-idp` prints a stable URL.
#[derive(Debug, Clone)]
pub struct MockIdpConfig {
    pub bind_addr: SocketAddr,
    pub clients: Vec<ClientConfig>,
    pub users: Vec<UserConfig>,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub rotate_refresh_tokens: bool,
    pub authorization_code_ttl_secs: u64,
    /// Seed for deterministic RSA keypair generation. `None` draws from OS
    /// entropy, so `jwks.json` (and every id_token signature) differs
    /// across process restarts; a fixed seed makes them reproducible for
    /// golden-file style tests.
    pub rsa_seed: Option<u64>,
}

impl Default for MockIdpConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            clients: vec![ClientConfig {
                client_id: "session-broker-dev".to_owned(),
                client_secret: Some("dev-secret".to_owned()),
                redirect_uris: vec!["http://localhost:8080/auth/callback".to_owned()],
            }],
            users: vec![UserConfig {
                subject: "user-1".to_owned(),
                email: "dev.user@example.test".to_owned(),
                name: "Dev User".to_owned(),
            }],
            access_token_ttl_secs: 300,
            refresh_token_ttl_secs: 14 * 24 * 3600,
            rotate_refresh_tokens: false,
            authorization_code_ttl_secs: 60,
            rsa_seed: None,
        }
    }
}

/// CLI/env surface for the `mock-idp` binary.
///
/// Only a single client and a single user can be configured this way; a
/// library caller that needs several of either builds [`MockIdpConfig`]
/// directly instead of going through here.
#[derive(Debug, Parser)]
#[command(
    name = "mock-idp",
    about = "Mock OpenID Connect provider (test fixture — do not deploy)"
)]
pub struct Cli {
    /// Address to bind. Fixed (not ephemeral) by default so `cargo run`
    /// prints a stable, bookmarkable URL.
    #[arg(long, env = "MOCK_IDP_BIND", default_value = "127.0.0.1:8090")]
    pub bind_addr: SocketAddr,

    #[arg(long, env = "MOCK_IDP_CLIENT_ID", default_value = "session-broker-dev")]
    pub client_id: String,

    #[arg(long, env = "MOCK_IDP_CLIENT_SECRET", default_value = "dev-secret")]
    pub client_secret: String,

    /// Comma-separated exact-match redirect URIs for `client_id`.
    #[arg(
        long,
        env = "MOCK_IDP_REDIRECT_URIS",
        default_value = "http://localhost:8080/auth/callback",
        value_delimiter = ','
    )]
    pub redirect_uris: Vec<String>,

    #[arg(long, env = "MOCK_IDP_SUBJECT", default_value = "user-1")]
    pub subject: String,

    #[arg(long, env = "MOCK_IDP_EMAIL", default_value = "dev.user@example.test")]
    pub email: String,

    #[arg(long, env = "MOCK_IDP_NAME", default_value = "Dev User")]
    pub name: String,

    #[arg(long, env = "MOCK_IDP_ACCESS_TOKEN_TTL_SECS", default_value_t = 300)]
    pub access_token_ttl_secs: u64,

    #[arg(
        long,
        env = "MOCK_IDP_REFRESH_TOKEN_TTL_SECS",
        default_value_t = 1_209_600
    )]
    pub refresh_token_ttl_secs: u64,

    #[arg(long, env = "MOCK_IDP_ROTATE_REFRESH_TOKENS", default_value_t = false)]
    pub rotate_refresh_tokens: bool,

    #[arg(long, env = "MOCK_IDP_AUTH_CODE_TTL_SECS", default_value_t = 60)]
    pub authorization_code_ttl_secs: u64,

    /// Fix the RSA signing keypair across restarts (useful when a
    /// downstream dev environment caches `jwks.json`).
    #[arg(long, env = "MOCK_IDP_RSA_SEED")]
    pub rsa_seed: Option<u64>,
}

impl From<Cli> for MockIdpConfig {
    fn from(cli: Cli) -> Self {
        Self {
            bind_addr: cli.bind_addr,
            clients: vec![ClientConfig {
                client_id: cli.client_id,
                client_secret: Some(cli.client_secret),
                redirect_uris: cli.redirect_uris,
            }],
            users: vec![UserConfig {
                subject: cli.subject,
                email: cli.email,
                name: cli.name,
            }],
            access_token_ttl_secs: cli.access_token_ttl_secs,
            refresh_token_ttl_secs: cli.refresh_token_ttl_secs,
            rotate_refresh_tokens: cli.rotate_refresh_tokens,
            authorization_code_ttl_secs: cli.authorization_code_ttl_secs,
            rsa_seed: cli.rsa_seed,
        }
    }
}
