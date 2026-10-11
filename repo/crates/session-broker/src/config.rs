//! Zero-config startup settings, loaded from the environment with an
//! optional TOML file underneath.
//!
//! Precedence, highest first: an environment variable (`BROKER_<FIELD>`,
//! upper-cased) beats a value from the config file, which beats the built-in
//! default. This means a bare `session-broker` binary with no file and no
//! env vars boots (the "single binary, zero-config" promise in
//! `docs/architecture/implementation-strategy.md` §1) — it simply comes up
//! with no upstream OIDC issuer configured, which is a valid, inert state.
//! Setting `oidc_issuer_url` without the rest of the OIDC fields is the one
//! thing that must fail loudly (see [`BrokerConfig::load`]).
//!
//! No TOML-parsing crate is in this crate's `Cargo.toml` (only `base64`,
//! `dashmap`, `rand`, `rusqlite`, `serde`, `serde_json`, `sha2`, `smallvec`,
//! `thiserror`, `tracing`, `zeroize` are dependencies, and adding one is out
//! of scope for this milestone), so [`parse_simple_toml`] is a small
//! hand-rolled subset: `key = value` pairs, `#` comments, blank lines, and
//! `[section]` headers that are accepted but ignored (this config is flat,
//! so sections carry no namespacing). That covers every shape this config
//! needs — quoted strings, bare words, integers, booleans — without pulling
//! in a general-purpose parser for it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::session::{RevocationPolicy, SessionPolicy};

/// Everything the broker needs to start, validated once at boot so a
/// misconfiguration is a startup failure, not a first-request surprise.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Public listener: `/auth/*`, `/session/*`, `/proxy/*`.
    pub bind_addr: SocketAddr,
    /// Separate listener for `/internal/token` (INV-11, ADR resolution #6:
    /// "second bind, default-on"). Never the same interface as `bind_addr`
    /// in a hardened deployment, though nothing here enforces that — it is a
    /// deployment-topology decision, not a parseable invariant.
    pub internal_bind_addr: SocketAddr,
    /// This broker's own externally-visible origin, used to build the OIDC
    /// redirect URI default and any self-referential links. Must be an
    /// absolute `http(s)://` URL.
    pub base_url: String,
    /// SQLite file path (§5). Relative paths resolve against the process's
    /// working directory.
    pub db_path: PathBuf,
    /// Keyfile backing the (currently not-yet-real, see `store::repo`
    /// module docs) at-rest encryption of custody tokens. Resolved decision
    /// #7: keyfile beside the DB, env override.
    pub keyfile_path: PathBuf,
    pub oidc: OidcConfig,
    session_policy: SessionPolicy,
    /// Where `/auth/callback` sends the browser on OAuth failure (§4).
    pub error_page_path: String,
    /// Shared secret guarding `/admin/*`.
    ///
    /// Deliberately NOT the same value as `broker_api_key`: a key that can mint
    /// keys is strictly more powerful than one that exchanges a session for a
    /// token, and sharing one would let every backend service issue credentials
    /// for itself. `None` disables the admin lane.
    pub admin_api_key: Option<ClientSecret>,
    /// Shared secret backends present on `/internal/token` (INV-11, ADR-0007).
    ///
    /// `None` disables the lane entirely rather than leaving it open — an
    /// unconfigured token-exchange endpoint that answered anyone would hand
    /// out upstream grants to whoever asked.
    pub broker_api_key: Option<ClientSecret>,
    /// The diagnostics plane (ADR-0014). Sinks and format are settled here, at
    /// boot, and not by the console: a browser tool holding the admin key must
    /// not be able to redirect the record. Verbosity alone is runtime-mutable.
    pub log: crate::telemetry::LogConfig,
    /// Serves `GET /metrics` on the internal listener.
    pub metrics_enabled: bool,
    /// The audit plane (ADR-0015).
    pub audit: crate::audit::AuditConfig,
    /// How long a provably-dead session row is kept before the reaper removes
    /// it (M6). `0` disables reaping — the pre-M6 behaviour, and unbounded.
    pub reap_after_secs: u64,
    /// Rate limiting (M6). See [`crate::ratelimit`] for why the client-IP
    /// source has to be named rather than inferred.
    pub rate_limit: RateLimitConfig,
    /// Largest request body any endpoint reads (`http::hardening`).
    pub max_body_bytes: usize,
    /// Handler deadline in seconds; `0` disables it. The SSE stream is exempt.
    pub request_timeout_secs: u64,
    /// How long shutdown waits for in-flight requests before giving up and
    /// flushing the store anyway. Long-lived SSE streams never finish on their
    /// own, so without a bound a deploy would hang on the first open tab.
    pub shutdown_grace_secs: u64,
    /// Pause between `/readyz` going 503 and the listeners closing, so a load
    /// balancer or Kubernetes endpoint controller has time to stop routing here
    /// first. `0` closes immediately — right for a single node behind nothing.
    pub shutdown_drain_delay_secs: u64,
    /// The token issuer (docs/design/token-issuer-scope.md). `None` leaves the
    /// feature off: no signing key is created and the issuer routes answer 501.
    pub issuer: Option<IssuerConfig>,
}

/// Settings for the token issuer. Present only when `token_issuer` and
/// `issuer_audiences` are both set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerConfig {
    /// The `iss` claim and the metadata `issuer`, without a trailing slash.
    pub issuer: String,
    /// Audiences a principal may be issued tokens for.
    pub audiences: Vec<String>,
    /// Default lifetime of a machine token.
    pub machine_ttl_secs: u64,
    /// Default lifetime of a user token (also capped by the session).
    pub user_ttl_secs: u64,
    /// Longest lifetime any token may have. A superseded signing key stays
    /// published this long after its successor takes over.
    pub max_ttl_secs: u64,
    /// How long a new signing key is published before it signs.
    pub publish_lead_secs: u64,
    /// `max-age` on the key set and metadata documents.
    pub jwks_max_age_secs: u64,
    /// Where the key set is served: `base_url` + `/auth/jwks.json`.
    pub jwks_uri: String,
    /// Where machine tokens are issued: `base_url` + `/auth/token`.
    pub token_endpoint: String,
    /// The tenant a signed-in user gets a token for when the broker holds no
    /// grant row for them at all, so a single-tenant install needs no admin
    /// step. `None` requires an explicit grant for everyone.
    pub default_user_tenant: Option<String>,
    /// The roles that default carries.
    pub default_user_roles: Vec<String>,
}

impl IssuerConfig {
    pub fn key_policy(&self) -> crate::issuer::KeyPolicy {
        crate::issuer::KeyPolicy {
            publish_lead_secs: self.publish_lead_secs,
            max_ttl_secs: self.max_ttl_secs,
        }
    }

    /// True for an `http://` issuer whose host is not loopback. Allowed (TLS is
    /// the operator's call) but worth one line in the log at start.
    pub fn is_plaintext_off_loopback(&self) -> bool {
        let Some(rest) = self.issuer.strip_prefix("http://") else {
            return false;
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = match authority.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or(""),
            None => authority.split(':').next().unwrap_or(""),
        };
        !matches!(host, "localhost" | "127.0.0.1" | "::1")
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Header naming the real client, appended by a trusted proxy. Unset means
    /// the PUBLIC lane is not limited at all — behind an edge every request
    /// shares one peer, so keying on it would bucket the whole user base
    /// together and the first trip would lock everyone out.
    pub client_ip_header: Option<String>,
    /// `/auth/login` starts a server-side transaction per call (INV-3).
    pub login_burst: u32,
    pub login_per_secs: u64,
    /// Wrong admin key or wrong backend API key. Both are shared secrets with
    /// no lockout of their own.
    pub auth_failure_burst: u32,
    pub auth_failure_per_secs: u64,
    /// Distinct keys tracked per limiter before it fails closed.
    pub max_tracked: usize,
}

impl Default for RateLimitConfig {
    fn default() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            client_ip_header: None,
            login_burst: 30,
            login_per_secs: 60,
            // Ten wrong keys a minute leaves an operator fat-fingering a paste
            // unbothered and makes an online guess against a 32-char secret
            // hopeless, which is the whole distance this needs to cover.
            auth_failure_burst: 10,
            auth_failure_per_secs: 60,
            max_tracked: 16_384,
        }
    }
}

impl BrokerConfig {
    /// The tunables the rest of the crate (`session.rs`, and later
    /// `keepalive.rs`) should read, rather than reaching into config
    /// directly. Cheap: [`SessionPolicy`] is `Copy`.
    pub fn session_policy(&self) -> SessionPolicy {
        self.session_policy
    }

    /// Load from the real process environment plus an optional TOML file
    /// (`BROKER_CONFIG_FILE`, or `./session-broker.toml` if that env var is
    /// unset and the file happens to exist), then validate.
    ///
    /// Fails loudly (rather than at first request) on: a `base_url` that
    /// isn't an absolute `http(s)://` URL; an `oidc_issuer_url` configured
    /// without an `oidc_client_secret`; or `idle_ttl_secs` exceeding
    /// `absolute_ttl_secs` (idle expiry sliding past the absolute ceiling
    /// would make the ceiling meaningless).
    pub fn load() -> Result<BrokerConfig, ConfigError> {
        let sources = Sources {
            file: load_file_settings()?,
        };
        Self::from_sources(&sources)
    }

    fn from_sources(sources: &Sources) -> Result<BrokerConfig, ConfigError> {
        let bind_addr = parse_field(sources, "bind_addr", "0.0.0.0:8080")?;
        let internal_bind_addr = parse_field(sources, "internal_bind_addr", "127.0.0.1:8090")?;

        let base_url = sources.get_or("base_url", "http://localhost:8080");
        validate_http_url("base_url", &base_url)?;

        let db_path = PathBuf::from(sources.get_or("db_path", "session-broker.db"));
        let keyfile_path = PathBuf::from(sources.get_or("keyfile_path", "session-broker.key"));

        let issuer_url = sources.get("oidc_issuer_url");
        let client_id = sources.get("oidc_client_id");
        let client_secret = sources.get("oidc_client_secret").map(ClientSecret::new);
        // The redirect URI must match what is registered at the IdP, which for the
        // single-origin topology (INV-10) is always this broker's own callback —
        // so it is derived rather than demanded, and only an unusual edge layout
        // needs to override it.
        let redirect_uri = sources.get("oidc_redirect_uri").or_else(|| {
            issuer_url
                .is_some()
                .then(|| format!("{}/auth/callback", base_url.trim_end_matches('/')))
        });
        let scopes = sources
            .get("oidc_scopes")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["openid".to_owned(), "offline_access".to_owned()]);

        // The zero-config default has no issuer at all, which is a valid,
        // inert boot state. The moment an operator points at an issuer,
        // though, half-configured OIDC must fail at startup rather than at
        // the first `/auth/login` — a missing secret there would otherwise
        // surface as an opaque token-exchange failure deep in `oauth.rs`.
        if issuer_url.is_some() && client_secret.is_none() {
            return Err(ConfigError::Invalid {
                field: "oidc_client_secret",
                message: "required when oidc_issuer_url is configured".to_owned(),
            });
        }

        if issuer_url.is_some() && client_id.is_none() {
            return Err(ConfigError::Invalid {
                field: "oidc_client_id",
                message: "required when oidc_issuer_url is configured".to_owned(),
            });
        }

        let session_policy = SessionPolicy {
            gen_ttl_secs: parse_field(sources, "gen_ttl_secs", "600")?,
            grace_secs: parse_field(sources, "grace_secs", "60")?,
            coalesce_secs: parse_field(sources, "coalesce_secs", "30")?,
            idle_ttl_secs: parse_field(sources, "idle_ttl_secs", "604800")?,
            absolute_ttl_secs: parse_field(sources, "absolute_ttl_secs", "2592000")?,
            max_live_gens: parse_field(sources, "max_live_gens", "4")?,
            retired_memory: parse_field(sources, "retired_memory", "8")?,
            on_upstream_revoked: parse_revocation_policy(sources)?,
        };

        if session_policy.idle_ttl_secs > session_policy.absolute_ttl_secs {
            return Err(ConfigError::Invalid {
                field: "idle_ttl_secs",
                message: format!(
                    "idle TTL ({}) must not exceed absolute TTL ({}) — idle slide could \
                     otherwise outrun the hard ceiling",
                    session_policy.idle_ttl_secs, session_policy.absolute_ttl_secs
                ),
            });
        }

        let error_page_path = sources.get_or("error_page_path", "/error");

        // Read as `api_key` so the environment variable is `BROKER_API_KEY`
        // rather than `BROKER_BROKER_API_KEY`. ADR-0007 names the concept
        // `broker_api_key` from the *backend's* point of view — where it is
        // the broker's key among several — and that is the name the field and
        // the docs keep.
        //
        // Short keys are refused rather than warned about: this one secret is
        // half of what stands between a caller and every user's upstream grant,
        // and a memorable one is a guessable one.
        let broker_api_key = sources.get("api_key");
        let admin_api_key = sources.get("admin_api_key");
        for (field, value) in [
            ("api_key", &broker_api_key),
            ("admin_api_key", &admin_api_key),
        ] {
            if let Some(key) = value {
                if key.len() < 32 {
                    return Err(ConfigError::Invalid {
                        field: if field == "api_key" {
                            "broker_api_key"
                        } else {
                            "admin_api_key"
                        },
                        message: format!(
                            "must be at least 32 characters; got {}. A memorable key is a \
                             guessable one, and this is half of what stands between a caller \
                             and every user's upstream grant.",
                            key.len()
                        ),
                    });
                }
            }
        }

        let log = crate::telemetry::LogConfig {
            format: parse_field(sources, "log_format", "text")?,
            // Kept identical to what `main.rs` used to hard-code, so upgrading
            // changes what is *configurable*, not what is emitted by default.
            // `broker=info` is load-bearing, not decoration. Events in this
            // service carry explicit targets — `broker::audit`, `broker::http`,
            // `broker::authz`, `broker::telemetry` — and an `EnvFilter`
            // directive matches the TARGET, not the crate. Without a `broker`
            // directive, `session_broker=info` matches the module-path events
            // and silently drops every one of the named ones, including the
            // audit stream that ADR-0014 calls the long-term archive.
            default_filter: sources.get_or(
                "log_level",
                "session_broker=info,broker=info,tower_http=warn",
            ),
            file: sources.get("log_file").map(PathBuf::from),
            file_rotation: parse_field(sources, "log_file_rotation", "daily")?,
            queue_capacity: parse_field(sources, "log_queue_capacity", "16384")?,
            override_max_secs: parse_field(sources, "log_level_override_max_secs", "3600")?,
        };
        let metrics_enabled = parse_bool(sources, "metrics_enabled", true)?;

        // A day, not an hour. Dead rows are inert, and keeping them briefly is
        // what lets an operator answer "what happened to that session?" from the
        // store rather than only from the audit trail. The audit rows outlive
        // them by design (90 days), so the history is not what is being pruned
        // here — only the working set.
        let reap_after_secs = parse_field(sources, "reap_after_secs", "86400")?;

        let max_body_bytes = parse_field(sources, "max_body_bytes", "65536")?;
        let request_timeout_secs = parse_field(sources, "request_timeout_secs", "30")?;
        let shutdown_grace_secs = parse_field(sources, "shutdown_grace_secs", "15")?;
        let shutdown_drain_delay_secs = parse_field(sources, "shutdown_drain_delay_secs", "0")?;

        let defaults = RateLimitConfig::default();
        let rate_limit = RateLimitConfig {
            enabled: parse_bool(sources, "rate_limit_enabled", defaults.enabled)?,
            client_ip_header: sources
                .get("rate_limit_client_ip_header")
                .map(|h| h.to_ascii_lowercase()),
            login_burst: parse_field(sources, "rate_limit_login_burst", "30")?,
            login_per_secs: parse_field(sources, "rate_limit_login_per_secs", "60")?,
            auth_failure_burst: parse_field(sources, "rate_limit_auth_failure_burst", "10")?,
            auth_failure_per_secs: parse_field(sources, "rate_limit_auth_failure_per_secs", "60")?,
            max_tracked: parse_field(sources, "rate_limit_max_tracked", "16384")?,
        };

        let audit = crate::audit::AuditConfig {
            retention_days: parse_field(sources, "audit_retention_days", "90")?,
            queue_capacity: parse_field(sources, "audit_queue_capacity", "8192")?,
            coalesce_secs: parse_field(sources, "audit_coalesce_secs", "300")?,
            record_rotations: parse_bool(sources, "audit_record_rotations", false)?,
            subject_mode: parse_field(sources, "audit_subject_mode", "plain")?,
        };
        if audit.queue_capacity == 0 {
            return Err(ConfigError::Invalid {
                field: "audit_queue_capacity",
                message: "must be at least 1; a zero-capacity queue drops every \
                          Tier-B audit event, which is a silent record, not a fast one"
                    .to_owned(),
            });
        }

        let issuer = issuer_config(sources, &base_url)?;

        Ok(BrokerConfig {
            bind_addr,
            internal_bind_addr,
            base_url,
            db_path,
            keyfile_path,
            oidc: OidcConfig {
                issuer_url,
                client_id,
                client_secret,
                scopes,
                redirect_uri,
            },
            session_policy,
            error_page_path,
            broker_api_key: broker_api_key.map(ClientSecret::new),
            admin_api_key: admin_api_key.map(ClientSecret::new),
            log,
            metrics_enabled,
            audit,
            reap_after_secs,
            rate_limit,
            max_body_bytes,
            request_timeout_secs,
            shutdown_grace_secs,
            shutdown_drain_delay_secs,
            issuer,
        })
    }
}

/// Upstream OIDC provider settings (§4: `/auth/login`, `/auth/callback`).
/// `None` fields mean "OIDC not configured" — a valid boot state as long as
/// `issuer_url` is also `None` (enforced in [`BrokerConfig::load`]).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<ClientSecret>,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
}

/// The OIDC client secret, held the same way `token.rs` holds session
/// tokens: zeroized on drop, no `Debug`/`Display` that could leak it into a
/// log line.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientSecret(String);

impl ClientSecret {
    fn new(value: String) -> ClientSecret {
        ClientSecret(value)
    }

    /// The only way to read the plaintext back out.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecret(redacted)")
    }
}

impl PartialEq for ClientSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for ClientSecret {}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid value for {field}: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },
    #[error("failed to read config file {path:?}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Merged view over the two lower-precedence sources (env still wins — see
/// [`Sources::get`]); the file contents, keyed by the same lower-case field
/// name used in `BROKER_<FIELD>`.
struct Sources {
    file: HashMap<String, String>,
}

impl Sources {
    /// Env var wins, then the file, then `None` (caller supplies the
    /// default). Empty env vars are treated as unset rather than as an
    /// explicit empty string — `BROKER_OIDC_CLIENT_ID=` left behind by a
    /// shell template should not silently defeat the file's value.
    fn get(&self, field: &str) -> Option<String> {
        let env_key = format!("BROKER_{}", field.to_ascii_uppercase());
        std::env::var(env_key)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| self.file.get(field).cloned())
    }

    fn get_or(&self, field: &str, default: &str) -> String {
        self.get(field).unwrap_or_else(|| default.to_owned())
    }
}

fn parse_field<T>(sources: &Sources, field: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = sources.get_or(field, default);
    raw.parse::<T>().map_err(|e| ConfigError::Invalid {
        field,
        message: format!("{e} (value: {raw:?})"),
    })
}

/// `true`/`false`, plus the spellings people actually type in a TOML file or a
/// Kubernetes manifest. Anything else is an error rather than a silent `false`:
/// `metrics_enabled = "yes"` quietly turning metrics off is the kind of
/// misconfiguration nobody notices until they need the graph.
fn parse_bool(sources: &Sources, field: &'static str, default: bool) -> Result<bool, ConfigError> {
    let raw = sources.get_or(field, if default { "true" } else { "false" });
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(ConfigError::Invalid {
            field,
            message: format!("must be a boolean, got {other:?}"),
        }),
    }
}

fn parse_revocation_policy(sources: &Sources) -> Result<RevocationPolicy, ConfigError> {
    match sources
        .get_or("on_upstream_revoked", "kill")
        .to_ascii_lowercase()
        .as_str()
    {
        "kill" => Ok(RevocationPolicy::Kill),
        "degrade" => Ok(RevocationPolicy::Degrade),
        other => Err(ConfigError::Invalid {
            field: "on_upstream_revoked",
            message: format!("must be \"kill\" or \"degrade\", got {other:?}"),
        }),
    }
}

/// The token issuer is off unless both `token_issuer` and `issuer_audiences` are
/// set; one without the other is a startup failure, as half-configured OIDC is.
fn issuer_config(sources: &Sources, base_url: &str) -> Result<Option<IssuerConfig>, ConfigError> {
    let invalid = |field: &'static str, message: String| ConfigError::Invalid { field, message };
    let (issuer, audiences) = match (sources.get("token_issuer"), sources.get("issuer_audiences")) {
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(invalid(
                "issuer_audiences",
                "required when token_issuer is configured".to_owned(),
            ))
        }
        (None, Some(_)) => {
            return Err(invalid(
                "token_issuer",
                "required when issuer_audiences is configured".to_owned(),
            ))
        }
        (Some(issuer), Some(audiences)) => (issuer, audiences),
    };

    validate_http_url("token_issuer", &issuer)?;
    if issuer.contains(['?', '#']) {
        return Err(invalid(
            "token_issuer",
            format!("must not carry a query or fragment (got {issuer:?})"),
        ));
    }
    let issuer = issuer.trim_end_matches('/').to_owned();
    let base = base_url.trim_end_matches('/');
    if issuer != base && !issuer.starts_with(&format!("{base}/")) {
        return Err(invalid(
            "token_issuer",
            format!("must be base_url ({base}) or a URL under it (got {issuer:?})"),
        ));
    }

    let mut list: Vec<String> = Vec::new();
    for audience in audiences.split(',').map(str::trim) {
        if audience.is_empty()
            || audience.chars().count() > 128
            || audience
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid(
                "issuer_audiences",
                format!(
                    "a comma-separated list of 1 to 128 character words without spaces \
                     (got {audiences:?})"
                ),
            ));
        }
        if !list.iter().any(|a| a == audience) {
            list.push(audience.to_owned());
        }
    }

    let machine_ttl_secs: u64 = parse_field(sources, "issuer_machine_ttl_secs", "86400")?;
    let user_ttl_secs: u64 = parse_field(sources, "issuer_user_ttl_secs", "3600")?;
    let max_ttl_secs: u64 = parse_field(sources, "issuer_max_ttl_secs", "2592000")?;
    let publish_lead_secs: u64 = parse_field(sources, "signing_key_publish_lead_secs", "86400")?;
    let jwks_max_age_secs: u64 = parse_field(sources, "issuer_jwks_max_age_secs", "300")?;
    if !(1..=MAX_TOKEN_TTL_SECS).contains(&max_ttl_secs) {
        return Err(invalid(
            "issuer_max_ttl_secs",
            format!("must be between 1 and {MAX_TOKEN_TTL_SECS} (got {max_ttl_secs})"),
        ));
    }
    for (field, value) in [
        ("issuer_machine_ttl_secs", machine_ttl_secs),
        ("issuer_user_ttl_secs", user_ttl_secs),
    ] {
        if value == 0 || value > max_ttl_secs {
            return Err(invalid(
                field,
                format!("must be between 1 and issuer_max_ttl_secs ({max_ttl_secs}), got {value}"),
            ));
        }
    }
    // The rotate route refuses a lead past 30 days, and a lead of zero would
    // make every ordinary rotation the emergency kind.
    if !(1..=MAX_PUBLISH_LEAD_SECS).contains(&publish_lead_secs) {
        return Err(invalid(
            "signing_key_publish_lead_secs",
            format!("must be between 1 and {MAX_PUBLISH_LEAD_SECS} (got {publish_lead_secs})"),
        ));
    }
    if jwks_max_age_secs > 86_400 {
        return Err(invalid(
            "issuer_jwks_max_age_secs",
            format!("must be at most 86400 (got {jwks_max_age_secs})"),
        ));
    }

    // Empty in the file, or `none` anywhere (an empty environment variable
    // counts as unset), turns the default off.
    let default_user_tenant = match sources.get_or("default_user_tenant", "default").trim() {
        "" | "none" => None,
        slug if is_slug(slug) => Some(slug.to_owned()),
        other => {
            return Err(invalid(
                "default_user_tenant",
                format!("must be a tenant slug such as \"default\", or \"none\" (got {other:?})"),
            ))
        }
    };
    let roles = sources.get_or("default_user_roles", "viewer");
    let mut default_user_roles: Vec<String> = Vec::new();
    for role in roles.split(',').map(str::trim) {
        if role.is_empty()
            || role.chars().count() > 128
            || role.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid(
                "default_user_roles",
                format!(
                    "a comma-separated list of 1 to 128 character words without spaces \
                     (got {roles:?})"
                ),
            ));
        }
        if !default_user_roles.iter().any(|r| r == role) {
            default_user_roles.push(role.to_owned());
        }
    }

    Ok(Some(IssuerConfig {
        issuer,
        audiences: list,
        machine_ttl_secs,
        user_ttl_secs,
        max_ttl_secs,
        publish_lead_secs,
        jwks_max_age_secs,
        jwks_uri: format!("{base}/auth/jwks.json"),
        token_endpoint: format!("{base}/auth/token"),
        default_user_tenant,
        default_user_roles,
    }))
}

/// `^[a-z0-9][a-z0-9-]{0,62}$`, the tenant slug rule.
fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A token may live at most a year (the same bound as a principal's maximum).
const MAX_TOKEN_TTL_SECS: u64 = 31_536_000;
/// The rotate route's own bound on `activate_in_secs`.
const MAX_PUBLISH_LEAD_SECS: u64 = 2_592_000;

/// Minimal manual check: absolute `http://` or `https://`, non-empty host,
/// no whitespace. Deliberately not a full URL parser (no `url` crate in this
/// crate's manifest either) — just enough to catch the startup mistakes that
/// matter (a bare hostname, a typo'd scheme, a copy-pasted value with a
/// trailing space).
fn validate_http_url(field: &'static str, url: &str) -> Result<(), ConfigError> {
    if url.chars().any(char::is_whitespace) {
        return Err(ConfigError::Invalid {
            field,
            message: format!("must not contain whitespace (got {url:?})"),
        });
    }
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return Err(ConfigError::Invalid {
            field,
            message: format!("must start with http:// or https:// (got {url:?})"),
        });
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_only = host.split(':').next().unwrap_or("");
    if host_only.is_empty() {
        return Err(ConfigError::Invalid {
            field,
            message: format!("missing host (got {url:?})"),
        });
    }
    Ok(())
}

/// Locate and read the optional TOML file: `BROKER_CONFIG_FILE` if set
/// (missing file at that path is an error — the operator asked for it
/// explicitly), else `./session-broker.toml` if it happens to exist (silent
/// zero-config fallback, no error if absent).
fn load_file_settings() -> Result<HashMap<String, String>, ConfigError> {
    let path = match std::env::var("BROKER_CONFIG_FILE") {
        Ok(p) => Some(PathBuf::from(p)),
        Err(_) => {
            let default = PathBuf::from("session-broker.toml");
            default.exists().then_some(default)
        }
    };
    let Some(path) = path else {
        return Ok(HashMap::new());
    };
    let contents =
        std::fs::read_to_string(&path).map_err(|source| ConfigError::ReadFile { path, source })?;
    Ok(parse_simple_toml(&contents))
}

/// See the module docs for why this exists instead of a `toml` dependency.
fn parse_simple_toml(input: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = if let Some(quoted) = value.strip_prefix('"') {
            quoted.strip_suffix('"').unwrap_or(quoted)
        } else {
            // Unquoted (bare word, integer, bool): a trailing `# comment` is
            // fair game to strip since it cannot contain a literal `#`.
            value.split('#').next().unwrap_or(value).trim()
        };
        out.insert(key.trim().to_owned(), value.to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // `Sources::get` reads real process env vars regardless of what's in a
    // test's own `file` map (env always wins — see `Sources::get`), and
    // `cargo test` runs tests in parallel within one process. Every test
    // that resolves a `Sources` (directly or via `BrokerConfig::load`) must
    // hold this lock for its duration, not just the tests that themselves
    // set a `BROKER_*` var, or an unrelated test can observe another test's
    // env var mid-flight.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sources(pairs: &[(&str, &str)]) -> Sources {
        Sources {
            file: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn defaults_load_with_no_settings_at_all() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[])).expect("zero-config boot must work");
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(cfg.internal_bind_addr, "127.0.0.1:8090".parse().unwrap());
        assert!(cfg.oidc.issuer_url.is_none());
        assert_eq!(cfg.session_policy().gen_ttl_secs, 600);
    }

    #[test]
    fn file_values_are_picked_up() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[
            ("bind_addr", "0.0.0.0:9999"),
            ("gen_ttl_secs", "120"),
        ]))
        .unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0:9999".parse().unwrap());
        assert_eq!(cfg.session_policy().gen_ttl_secs, 120);
    }

    #[test]
    fn env_var_overrides_file_value() {
        let _guard = lock();

        std::env::set_var("BROKER_BIND_ADDR", "0.0.0.0:7000");
        let result = BrokerConfig::from_sources(&sources(&[("bind_addr", "0.0.0.0:9999")]));
        std::env::remove_var("BROKER_BIND_ADDR");

        assert_eq!(result.unwrap().bind_addr, "0.0.0.0:7000".parse().unwrap());
    }

    #[test]
    fn bad_base_url_fails_loudly() {
        let _guard = lock();
        let err = BrokerConfig::from_sources(&sources(&[("base_url", "not-a-url")])).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "base_url",
                ..
            }
        ));
    }

    #[test]
    fn base_url_without_scheme_is_rejected() {
        let _guard = lock();
        let err = BrokerConfig::from_sources(&sources(&[("base_url", "example.com")])).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "base_url",
                ..
            }
        ));
    }

    #[test]
    fn issuer_without_client_secret_fails_loudly() {
        let _guard = lock();
        let err =
            BrokerConfig::from_sources(&sources(&[("oidc_issuer_url", "https://idp.example.com")]))
                .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "oidc_client_secret",
                ..
            }
        ));
    }

    #[test]
    fn issuer_with_client_secret_succeeds() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[
            ("oidc_issuer_url", "https://idp.example.com"),
            ("oidc_client_id", "broker"),
            ("oidc_client_secret", "shh"),
        ]))
        .unwrap();
        assert_eq!(cfg.oidc.client_secret.as_ref().unwrap().expose(), "shh");
    }

    #[test]
    fn transport_limits_default_and_can_be_overridden() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[])).unwrap();
        assert_eq!(cfg.max_body_bytes, 65_536);
        assert_eq!(cfg.request_timeout_secs, 30);
        assert_eq!(cfg.shutdown_grace_secs, 15);

        let cfg = BrokerConfig::from_sources(&sources(&[
            ("max_body_bytes", "1024"),
            ("request_timeout_secs", "0"),
            ("shutdown_grace_secs", "3"),
        ]))
        .unwrap();
        assert_eq!(cfg.max_body_bytes, 1024);
        assert_eq!(cfg.request_timeout_secs, 0);
        assert_eq!(cfg.shutdown_grace_secs, 3);

        let err = BrokerConfig::from_sources(&sources(&[("max_body_bytes", "lots")])).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "max_body_bytes",
                ..
            }
        ));
    }

    #[test]
    fn issuer_without_client_id_fails_at_boot_not_at_first_login() {
        let _guard = lock();
        let err = BrokerConfig::from_sources(&sources(&[
            ("oidc_issuer_url", "https://idp.example.com"),
            ("oidc_client_secret", "shh"),
        ]))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "oidc_client_id",
                ..
            }
        ));
    }

    #[test]
    fn the_redirect_uri_defaults_to_this_brokers_own_callback() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[
            ("base_url", "https://app.example.com/"),
            ("oidc_issuer_url", "https://idp.example.com"),
            ("oidc_client_id", "broker"),
            ("oidc_client_secret", "shh"),
        ]))
        .unwrap();
        assert_eq!(
            cfg.oidc.redirect_uri.as_deref(),
            Some("https://app.example.com/auth/callback")
        );

        let cfg = BrokerConfig::from_sources(&sources(&[
            ("base_url", "https://app.example.com"),
            ("oidc_issuer_url", "https://idp.example.com"),
            ("oidc_client_id", "broker"),
            ("oidc_client_secret", "shh"),
            ("oidc_redirect_uri", "https://edge.example.com/cb"),
        ]))
        .unwrap();
        assert_eq!(
            cfg.oidc.redirect_uri.as_deref(),
            Some("https://edge.example.com/cb")
        );
    }

    fn issuer_err(pairs: &[(&str, &str)]) -> &'static str {
        let _guard = lock();
        match BrokerConfig::from_sources(&sources(pairs)).unwrap_err() {
            ConfigError::Invalid { field, .. } => field,
            other => panic!("expected an Invalid error, got {other:?}"),
        }
    }

    const ISSUER_ON: [(&str, &str); 3] = [
        ("base_url", "https://broker.example.com"),
        ("token_issuer", "https://broker.example.com"),
        ("issuer_audiences", "logless"),
    ];

    fn issuer_with(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut pairs: Vec<_> = ISSUER_ON.to_vec();
        pairs.extend_from_slice(extra);
        pairs
    }

    #[test]
    fn the_issuer_is_off_by_default_and_on_with_its_defaults() {
        let _guard = lock();
        assert!(BrokerConfig::from_sources(&sources(&[]))
            .unwrap()
            .issuer
            .is_none());

        let cfg = BrokerConfig::from_sources(&sources(&ISSUER_ON)).unwrap();
        let issuer = cfg.issuer.unwrap();
        assert_eq!(issuer.issuer, "https://broker.example.com");
        assert_eq!(issuer.audiences, vec!["logless".to_owned()]);
        assert_eq!(issuer.machine_ttl_secs, 86_400);
        assert_eq!(issuer.user_ttl_secs, 3_600);
        assert_eq!(issuer.max_ttl_secs, 2_592_000);
        assert_eq!(issuer.publish_lead_secs, 86_400);
        assert_eq!(issuer.jwks_max_age_secs, 300);
        assert_eq!(issuer.jwks_uri, "https://broker.example.com/auth/jwks.json");
        assert_eq!(issuer.key_policy().publish_lead_secs, 86_400);
        assert_eq!(issuer.key_policy().max_ttl_secs, 2_592_000);
        assert_eq!(issuer.default_user_tenant.as_deref(), Some("default"));
        assert_eq!(issuer.default_user_roles, vec!["viewer".to_owned()]);
    }

    #[test]
    fn the_default_user_tenant_can_be_changed_or_switched_off() {
        let _guard = lock();
        let issuer = |extra: &[(&'static str, &'static str)]| {
            BrokerConfig::from_sources(&sources(&issuer_with(extra)))
                .unwrap()
                .issuer
                .unwrap()
        };
        let custom = issuer(&[
            ("default_user_tenant", "acme"),
            ("default_user_roles", " reader , writer,reader "),
        ]);
        assert_eq!(custom.default_user_tenant.as_deref(), Some("acme"));
        assert_eq!(
            custom.default_user_roles,
            vec!["reader".to_owned(), "writer".to_owned()]
        );
        assert_eq!(
            issuer(&[("default_user_tenant", "none")]).default_user_tenant,
            None
        );
        assert_eq!(
            issuer(&[("default_user_tenant", " ")]).default_user_tenant,
            None
        );
    }

    #[test]
    fn a_bad_default_user_tenant_or_role_fails_at_boot() {
        for (field, bad) in [
            ("default_user_tenant", "Acme"),
            ("default_user_tenant", "has space"),
            ("default_user_tenant", "-lead"),
            ("default_user_roles", "viewer,,admin"),
            ("default_user_roles", "two words"),
        ] {
            assert_eq!(issuer_err(&issuer_with(&[(field, bad)])), field, "{bad}");
        }
    }

    #[test]
    fn the_issuer_may_sit_under_base_url_and_audiences_are_a_trimmed_list() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[
            ("base_url", "https://example.com/broker/"),
            ("token_issuer", "https://example.com/broker/tenants/"),
            ("issuer_audiences", " logless , qw,logless "),
        ]))
        .unwrap();
        let issuer = cfg.issuer.unwrap();
        assert_eq!(issuer.issuer, "https://example.com/broker/tenants");
        assert_eq!(
            issuer.audiences,
            vec!["logless".to_owned(), "qw".to_owned()]
        );
        assert_eq!(issuer.jwks_uri, "https://example.com/broker/auth/jwks.json");
    }

    #[test]
    fn issuer_settings_need_each_other() {
        assert_eq!(
            issuer_err(&[("token_issuer", "http://localhost:8080")]),
            "issuer_audiences"
        );
        assert_eq!(
            issuer_err(&[("issuer_audiences", "logless")]),
            "token_issuer"
        );
    }

    #[test]
    fn a_token_issuer_outside_base_url_is_refused() {
        for bad in [
            "https://other.example.com",
            "https://broker.example.com.evil.net",
            "http://broker.example.com",
            "https://broker.example.com?x=1",
            "https://broker.example.com#frag",
            "broker.example.com",
        ] {
            assert_eq!(
                issuer_err(&[
                    ("base_url", "https://broker.example.com"),
                    ("token_issuer", bad),
                    ("issuer_audiences", "logless"),
                ]),
                "token_issuer",
                "{bad}"
            );
        }
    }

    #[test]
    fn bad_audiences_are_refused() {
        for bad in ["", ",", "a,,b", "has space", &"x".repeat(129)] {
            assert_eq!(
                issuer_err(&[
                    ("token_issuer", "http://localhost:8080"),
                    ("issuer_audiences", bad),
                ]),
                "issuer_audiences",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn issuer_numbers_are_bounded() {
        for (field, value) in [
            ("issuer_machine_ttl_secs", "0"),
            ("issuer_machine_ttl_secs", "99999999"),
            ("issuer_user_ttl_secs", "0"),
            ("issuer_user_ttl_secs", "3000000"),
            ("issuer_max_ttl_secs", "0"),
            ("issuer_max_ttl_secs", "31536001"),
            ("signing_key_publish_lead_secs", "0"),
            ("signing_key_publish_lead_secs", "2592001"),
            ("issuer_jwks_max_age_secs", "86401"),
            ("issuer_jwks_max_age_secs", "soon"),
        ] {
            assert_eq!(
                issuer_err(&issuer_with(&[(field, value)])),
                field,
                "{field}={value}"
            );
        }
        // Raising the ceiling makes a longer default legal.
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&issuer_with(&[
            ("issuer_max_ttl_secs", "7776000"),
            ("issuer_machine_ttl_secs", "7776000"),
        ])))
        .unwrap();
        assert_eq!(cfg.issuer.unwrap().machine_ttl_secs, 7_776_000);
    }

    #[test]
    fn plaintext_is_flagged_only_off_loopback_and_never_refused() {
        let _guard = lock();
        let flagged = |base: &str| {
            BrokerConfig::from_sources(&sources(&[
                ("base_url", base),
                ("token_issuer", base),
                ("issuer_audiences", "logless"),
            ]))
            .unwrap()
            .issuer
            .unwrap()
            .is_plaintext_off_loopback()
        };
        assert!(flagged("http://broker.internal:8080"));
        assert!(!flagged("https://broker.example.com"));
        assert!(!flagged("http://localhost:8080"));
        assert!(!flagged("http://127.0.0.1:8080"));
        assert!(!flagged("http://[::1]:8080"));
    }

    #[test]
    fn client_secret_debug_is_redacted() {
        let secret = ClientSecret::new("super-secret".to_owned());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn idle_ttl_exceeding_absolute_ttl_fails_loudly() {
        let _guard = lock();
        let err = BrokerConfig::from_sources(&sources(&[
            ("idle_ttl_secs", "1000"),
            ("absolute_ttl_secs", "500"),
        ]))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "idle_ttl_secs",
                ..
            }
        ));
    }

    #[test]
    fn bad_revocation_policy_fails_loudly() {
        let _guard = lock();
        let err = BrokerConfig::from_sources(&sources(&[("on_upstream_revoked", "explode")]))
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "on_upstream_revoked",
                ..
            }
        ));
    }

    #[test]
    fn scopes_default_to_openid_and_offline_access() {
        let _guard = lock();
        let cfg = BrokerConfig::from_sources(&sources(&[])).unwrap();
        assert_eq!(cfg.oidc.scopes, vec!["openid", "offline_access"]);
    }

    #[test]
    fn scopes_are_parsed_from_a_comma_list() {
        let _guard = lock();
        let cfg =
            BrokerConfig::from_sources(&sources(&[("oidc_scopes", "openid, email ,profile")]))
                .unwrap();
        assert_eq!(cfg.oidc.scopes, vec!["openid", "email", "profile"]);
    }

    #[test]
    fn simple_toml_parses_quoted_and_bare_values_with_comments() {
        let parsed = parse_simple_toml(
            r#"
            # a comment
            [section]
            bind_addr = "0.0.0.0:8080"
            gen_ttl_secs = 600 # inline comment
            on_upstream_revoked = kill
            "#,
        );
        assert_eq!(
            parsed.get("bind_addr").map(String::as_str),
            Some("0.0.0.0:8080")
        );
        assert_eq!(parsed.get("gen_ttl_secs").map(String::as_str), Some("600"));
        assert_eq!(
            parsed.get("on_upstream_revoked").map(String::as_str),
            Some("kill")
        );
    }
}
