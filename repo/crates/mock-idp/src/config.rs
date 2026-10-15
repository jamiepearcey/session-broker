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
/// Only a single client can be configured this way (any number of users);
/// a library caller that needs several clients builds [`MockIdpConfig`]
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

    /// Canned users, each `subject|email|name`. Repeat `--user`, or give
    /// `MOCK_IDP_USERS` as a `;`-separated list. The first user is the one
    /// `/authorize` logs in when `login_as` is omitted and only one user is
    /// configured; with several, `/authorize` shows a chooser instead.
    #[arg(
        long = "user",
        env = "MOCK_IDP_USERS",
        default_value = "user-1|dev.user@example.test|Dev User",
        value_delimiter = ';',
        value_parser = parse_user
    )]
    pub users: Vec<UserConfig>,

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
            users: cli.users,
            access_token_ttl_secs: cli.access_token_ttl_secs,
            refresh_token_ttl_secs: cli.refresh_token_ttl_secs,
            rotate_refresh_tokens: cli.rotate_refresh_tokens,
            authorization_code_ttl_secs: cli.authorization_code_ttl_secs,
            rsa_seed: cli.rsa_seed,
        }
    }
}

/// Parse one `subject|email|name` user. All three parts must be non-empty;
/// `name` may itself contain `|` (everything after the second one).
fn parse_user(raw: &str) -> Result<UserConfig, String> {
    let mut parts = raw.splitn(3, '|').map(str::trim);
    let (Some(subject), Some(email), Some(name)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(format!("user {raw:?} must be subject|email|name"));
    };
    if subject.is_empty() || email.is_empty() || name.is_empty() {
        return Err(format!("user {raw:?} has an empty subject, email or name"));
    }
    Ok(UserConfig {
        subject: subject.to_owned(),
        email: email.to_owned(),
        name: name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_user() {
        let user = parse_user("alice|alice@example.test|Alice Analyst").unwrap();
        assert_eq!(user.subject, "alice");
        assert_eq!(user.email, "alice@example.test");
        assert_eq!(user.name, "Alice Analyst");
    }

    #[test]
    fn rejects_missing_or_empty_parts() {
        assert!(parse_user("alice|alice@example.test").is_err());
        assert!(parse_user("alice||Alice").is_err());
        assert!(parse_user("|a@example.test|Alice").is_err());
    }

    #[test]
    fn default_cli_is_the_single_user_setup() {
        let cli = Cli::parse_from(["mock-idp"]);
        let config: MockIdpConfig = cli.into();
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].subject, "user-1");
    }

    #[test]
    fn repeated_user_flags_build_several_users() {
        let cli = Cli::parse_from([
            "mock-idp",
            "--user",
            "alice|a@example.test|Alice",
            "--user",
            "bob|b@example.test|Bob",
        ]);
        let config: MockIdpConfig = cli.into();
        let subjects: Vec<_> = config.users.iter().map(|u| u.subject.as_str()).collect();
        assert_eq!(subjects, ["alice", "bob"]);
    }
}
