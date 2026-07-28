//! The diagnostics plane: logging setup, runtime verbosity control, and metrics
//! (ADR-0014).
//!
//! ## What lives here and what deliberately does not
//!
//! This module owns *content and cost*: what gets emitted, how it is formatted,
//! and the guarantee that emitting it never blocks a request. It does **not**
//! own transport. There is no HTTP appender, no syslog client, no OTLP
//! exporter, and there will not be one — a service holding every user's upstream
//! refresh token should not also own an outbound network path that can block,
//! retry, or be redirected. The deployment's collector reads stdout.
//!
//! ## Non-blocking is the load-bearing property
//!
//! `/authz` is on the per-request path of the whole platform (Envoy `ext_authz`)
//! and `/session/refresh` claims microseconds (INV-8). Both write log lines. So
//! every sink goes through [`tracing_appender::non_blocking`]: a bounded queue
//! drained by a dedicated thread. A `tracing::info!` costs a channel send, never
//! a `write(2)`, and a stalled stdout consumer drops lines instead of becoming
//! backpressure on the platform's request path.
//!
//! ## The audit plane is next door, not here
//!
//! [`crate::audit`] is the durable, queryable record (ADR-0015). Audit events
//! are *also* emitted here under target `broker::audit` at `info`, fail-open, so
//! a collector gets the long-term archive — but the store's copy is what the
//! console reads and what survives a broken log pipeline.

pub mod http;
pub mod metrics;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{reload, Layer, Registry};

/// The subscriber the format layers sit on top of.
///
/// Spelled out because the filter has to be the *innermost* layer — that is what
/// lets one reload handle turn verbosity down for every sink at once — which
/// means the boxed format layers are layered over `Registry + reload`, not over
/// a bare `Registry`. Naming it here keeps [`LogControl::reload`]'s type as the
/// plain `reload::Handle<EnvFilter, Registry>` an admin handler can hold.
type Filtered = tracing_subscriber::layer::Layered<reload::Layer<EnvFilter, Registry>, Registry>;

pub use metrics::Metrics;

/// Console output shape. `text` for a human at a terminal, `json` for anything
/// with a shipper in front of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl LogFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        }
    }
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<LogFormat, String> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "plain" | "human" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            other => Err(format!("must be \"text\" or \"json\", got {other:?}")),
        }
    }
}

/// How often the file sink starts a new file. Rotation only — the broker never
/// deletes a file it has closed; pruning is logrotate's job or the volume's.
/// Saying so here matters, because "the broker rotates logs" reads as "the
/// broker manages log disk", and it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRotation {
    Daily,
    Hourly,
    Never,
}

impl FileRotation {
    pub fn as_str(self) -> &'static str {
        match self {
            FileRotation::Daily => "daily",
            FileRotation::Hourly => "hourly",
            FileRotation::Never => "never",
        }
    }
}

impl std::str::FromStr for FileRotation {
    type Err = String;

    fn from_str(s: &str) -> Result<FileRotation, String> {
        match s.to_ascii_lowercase().as_str() {
            "daily" => Ok(FileRotation::Daily),
            "hourly" => Ok(FileRotation::Hourly),
            "never" | "none" => Ok(FileRotation::Never),
            other => Err(format!(
                "must be \"daily\", \"hourly\" or \"never\", got {other:?}"
            )),
        }
    }
}

/// Everything the diagnostics plane needs at boot. Comes from
/// [`crate::config::BrokerConfig`]; kept as its own struct so `telemetry::init`
/// can be driven from a test with three fields instead of a whole broker config.
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub format: LogFormat,
    /// The default `EnvFilter` directive. `RUST_LOG` still overrides it — an
    /// operator debugging a container should not have to find the config file.
    pub default_filter: String,
    /// Optional second sink. Unset (the recommended deployment) means stdout
    /// only.
    pub file: Option<PathBuf>,
    pub file_rotation: FileRotation,
    pub queue_capacity: usize,
    /// Ceiling on a console-requested temporary verbosity change. Bounded so
    /// that "turn the lights up during an incident" cannot become "the broker
    /// has been at trace since March".
    pub override_max_secs: u64,
}

impl Default for LogConfig {
    fn default() -> LogConfig {
        LogConfig {
            format: LogFormat::Text,
            default_filter: "session_broker=info,tower_http=warn".to_owned(),
            file: None,
            file_rotation: FileRotation::Daily,
            queue_capacity: 16_384,
            override_max_secs: 3_600,
        }
    }
}

/// A temporary verbosity change and its deadline.
#[derive(Debug, Clone)]
pub struct LevelOverride {
    pub filter: String,
    /// Epoch seconds. Past this, [`LogControl::expire_due_override`] restores
    /// the configured filter.
    pub expires_at: i64,
    /// Who asked for it, for the audit row and for the console.
    pub requested_by: Option<String>,
}

/// The runtime handle the admin lane holds.
///
/// It can change **how loud the diagnostics are**. It cannot change **where the
/// record goes** — sinks, retention and redaction are deployment config, applied
/// at restart. The line is deliberate (ADR-0015 §"Runtime controls"): a browser
/// tool holding the admin key must not be able to redirect or silence the audit
/// stream, because blinding the record is the first thing an attacker who
/// reaches that console would want to do.
pub struct LogControl {
    reload: reload::Handle<EnvFilter, Registry>,
    config: LogConfig,
    active: Mutex<Option<LevelOverride>>,
    /// Read by the metrics exposition without taking the mutex.
    override_active: AtomicBool,
    /// Kept alive for the process lifetime: dropping a guard flushes and stops
    /// that sink's writer thread, so losing one silently stops logging.
    _guards: Vec<tracing_appender::non_blocking::WorkerGuard>,
}

impl std::fmt::Debug for LogControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogControl")
            .field("format", &self.config.format)
            .field("default_filter", &self.config.default_filter)
            .field("override_active", &self.override_active())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LogControlError {
    #[error("{0} is not a valid log filter directive")]
    BadFilter(String),
    #[error("requested duration {requested}s exceeds the configured ceiling of {max}s")]
    TooLong { requested: u64, max: u64 },
    #[error("the subscriber is gone, so verbosity cannot be changed")]
    Detached,
}

impl LogControl {
    pub fn config(&self) -> &LogConfig {
        &self.config
    }

    pub fn override_active(&self) -> bool {
        self.override_active.load(Ordering::Relaxed)
    }

    /// The override in force, if any.
    pub fn current_override(&self) -> Option<LevelOverride> {
        self.active.lock().ok().and_then(|g| g.clone())
    }

    /// The directive actually in force right now.
    pub fn effective_filter(&self) -> String {
        self.current_override()
            .map(|o| o.filter)
            .unwrap_or_else(|| self.config.default_filter.clone())
    }

    /// Raise (or lower) verbosity until `expires_at`.
    ///
    /// Validated before it is applied: an unparseable directive would otherwise
    /// leave the subscriber filtering nothing, which is the loudest possible
    /// failure on a service that logs per request.
    pub fn set_override(
        &self,
        filter: &str,
        duration_secs: u64,
        now: i64,
        requested_by: Option<String>,
    ) -> Result<LevelOverride, LogControlError> {
        if duration_secs == 0 || duration_secs > self.config.override_max_secs {
            return Err(LogControlError::TooLong {
                requested: duration_secs,
                max: self.config.override_max_secs,
            });
        }
        let parsed = EnvFilter::try_new(filter)
            .map_err(|_| LogControlError::BadFilter(filter.to_owned()))?;

        self.reload
            .reload(parsed)
            .map_err(|_| LogControlError::Detached)?;

        let entry = LevelOverride {
            filter: filter.to_owned(),
            expires_at: now.saturating_add(duration_secs as i64),
            requested_by,
        };
        if let Ok(mut guard) = self.active.lock() {
            *guard = Some(entry.clone());
        }
        self.override_active.store(true, Ordering::Relaxed);
        tracing::warn!(
            target: "broker::telemetry",
            filter,
            expires_at = entry.expires_at,
            "log verbosity temporarily raised; it will restore itself"
        );
        Ok(entry)
    }

    /// Put the configured filter back. Idempotent — restoring when nothing is
    /// overridden is a no-op, which is what the console's "restore now" button
    /// wants when two operators press it.
    pub fn restore(&self) -> Result<bool, LogControlError> {
        let was = self.override_active.swap(false, Ordering::Relaxed);
        if let Ok(mut guard) = self.active.lock() {
            *guard = None;
        }
        if !was {
            return Ok(false);
        }
        let parsed = EnvFilter::try_new(&self.config.default_filter)
            .map_err(|_| LogControlError::BadFilter(self.config.default_filter.clone()))?;
        self.reload
            .reload(parsed)
            .map_err(|_| LogControlError::Detached)?;
        tracing::info!(target: "broker::telemetry", "log verbosity restored to the configured filter");
        Ok(true)
    }

    /// Called on a timer. Restores the configured filter once the deadline has
    /// passed.
    ///
    /// The deadline is enforced *here*, by a task, rather than by checking on
    /// the next admin request — otherwise a console tab that closes right after
    /// raising verbosity would leave it raised indefinitely, which is exactly
    /// the case the ceiling exists for.
    pub fn expire_due_override(&self, now: i64) -> bool {
        let due = matches!(self.current_override(), Some(o) if o.expires_at <= now);
        if due {
            let _ = self.restore();
        }
        due
    }
}

/// Install the subscriber and return the runtime handle.
///
/// Called once, first thing in `main`. Returns an error rather than panicking so
/// a bad `log_file` path fails the boot with a readable message instead of an
/// unwrap somewhere inside the appender.
pub fn init(config: LogConfig) -> Result<std::sync::Arc<LogControl>, String> {
    // RUST_LOG wins if it is set: an operator debugging a container should not
    // have to find and edit the config file to raise the level once.
    let initial = std::env::var("RUST_LOG")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| config.default_filter.clone());
    let filter = EnvFilter::try_new(&initial)
        .map_err(|e| format!("log_level {initial:?} is not a valid filter directive: {e}"))?;

    let (filter_layer, reload_handle) = reload::Layer::new(filter);

    let mut guards = Vec::new();
    let mut layers: Vec<Box<dyn Layer<Filtered> + Send + Sync>> = Vec::new();

    let (stdout_writer, stdout_guard) =
        tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(config.queue_capacity)
            // Lossy: under pressure, drop lines rather than block the caller. On the
            // /authz path "block the caller" means blocking a platform request on a
            // log write, which is never the right trade.
            .lossy(true)
            .finish(std::io::stdout());
    guards.push(stdout_guard);
    layers.push(fmt_layer(config.format, stdout_writer));

    if let Some(path) = &config.file {
        let directory = path.parent().filter(|p| !p.as_os_str().is_empty());
        let file_name = path
            .file_name()
            .ok_or_else(|| format!("log_file {} has no file name", path.display()))?;
        if let Some(dir) = directory {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("could not create log directory {}: {e}", dir.display()))?;
        }
        let appender = match config.file_rotation {
            FileRotation::Daily => tracing_appender::rolling::daily(
                directory.unwrap_or_else(|| std::path::Path::new(".")),
                file_name,
            ),
            FileRotation::Hourly => tracing_appender::rolling::hourly(
                directory.unwrap_or_else(|| std::path::Path::new(".")),
                file_name,
            ),
            FileRotation::Never => tracing_appender::rolling::never(
                directory.unwrap_or_else(|| std::path::Path::new(".")),
                file_name,
            ),
        };
        let (file_writer, file_guard) =
            tracing_appender::non_blocking::NonBlockingBuilder::default()
                .buffered_lines_limit(config.queue_capacity)
                .lossy(true)
                .finish(appender);
        guards.push(file_guard);
        // The file sink is always JSON regardless of `log_format`: a file exists
        // to be parsed later by something, whereas the console format exists to
        // be read now by a person. ANSI is off for the same reason.
        layers.push(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(file_writer)
                .boxed(),
        );
    }

    Registry::default()
        .with(filter_layer)
        .with(layers)
        .try_init()
        .map_err(|e| format!("a tracing subscriber is already installed: {e}"))?;

    Ok(std::sync::Arc::new(LogControl {
        reload: reload_handle,
        config,
        active: Mutex::new(None),
        override_active: AtomicBool::new(false),
        _guards: guards,
    }))
}

fn fmt_layer<W>(format: LogFormat, writer: W) -> Box<dyn Layer<Filtered> + Send + Sync>
where
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .boxed(),
        LogFormat::Text => tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(writer)
            .boxed(),
    }
}

/// Truncate a client address to a /24 (IPv4) or /48 (IPv6) prefix.
///
/// INV-12: a full client address is PII and is never logged or stored. A prefix
/// is enough for the one question the record actually asks of it — "did these
/// two generations come from somewhere plausibly different" (INV-6a) — and not
/// enough to identify a person.
pub fn ip_prefix(addr: &std::net::IpAddr) -> String {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

#[cfg(test)]
mod tests;
