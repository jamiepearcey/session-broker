//! The `session-broker` binary: config → store → rehydrate → session map →
//! custody + keepalive → two listeners → serve.
//!
//! ## The two listeners, and why they are separate
//!
//! * `bind_addr` carries `/auth/*`, `/session/*` and `/logout` — the browser's
//!   surface, reached through the SPA's own origin (INV-10, ADR-0012).
//! * `internal_bind_addr` carries `/internal/token` — the backend surface
//!   (INV-11). Separate so a hardened deployment can keep it off the public
//!   interface entirely; the lane still requires dual authentication either
//!   way, because a bind address is a deployment promise, not an enforced one.
//!
//! ## Boot order is load-bearing
//!
//! The store opens (which loads the custody encryption key), then sessions are
//! rehydrated from it, then the keepalive schedule is rebuilt, and only then do
//! the listeners start. Serving before rehydration would answer a live cookie
//! with "unknown session" and log the user out on a deploy — the exact failure
//! the durable token hashes exist to prevent.
//!
//! ## Still not wired, stated plainly
//!
//! * The `/proxy/*` browser lane (ADR-0007's other half) is not built. Nothing
//!   depends on it: backends use `/internal/token`.
//! * The `/proxy/*` browser lane is the only piece still unbuilt; see above.

use std::sync::Arc;

use axum::extract::Extension;
use session_broker::clock::{Clock, SystemClock, Timestamp};
use session_broker::config::BrokerConfig;
use session_broker::custody::{CustodySink, OidcUpstream, ScheduleRequest};
use session_broker::http::events::SessionEvents;
use session_broker::http::internal::InternalState;
use session_broker::http::{self, AppState, HttpConfig};
use session_broker::keepalive::{KeepalivePolicy, KeepaliveWorker, RandJitter};
use session_broker::oauth::OidcClient;
use session_broker::session::{Generation, RestoredSession, SessionMap};
use session_broker::store::{self, writer::Writer, Reader};
use session_broker::token::TokenHash;

/// How often the keepalive worker wakes when nothing arrives on its channel.
/// Short enough that a due custody is refreshed promptly, long enough to cost
/// nothing while idle.
const KEEPALIVE_IDLE_TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the audit retention sweep runs. Hourly is far more often than a
/// 90-day window needs; the point is that a broker which has been up for months
/// never accumulates a day's worth of overdue rows to delete in one transaction.
const AUDIT_PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// How often the reaper sweeps. Frequent enough that a busy deployment never
/// accumulates a big deletion, rare enough to cost nothing while idle.
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// INV-3's login-transaction TTL. A txn older than this is single-use-expired
/// and can never be redeemed, so it is pure residue.
const TXN_TTL_SECS: u64 = 600;

/// How often a due verbosity override is checked for expiry. The deadline is
/// enforced by a timer rather than on the next admin request, because the
/// console tab that raised the level is usually closed by the time it matters.
const LOG_OVERRIDE_TICK: std::time::Duration = std::time::Duration::from_secs(15);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Config is loaded BEFORE the subscriber, because the subscriber is now
    // configurable. A parse error here therefore has to survive going to stderr
    // unadorned — which it does, and which is better than installing a
    // subscriber the operator did not ask for in order to complain about the
    // one they did.
    let config = BrokerConfig::load()?;
    let log = session_broker::telemetry::init(config.log.clone())?;
    let metrics = session_broker::telemetry::Metrics::new();
    let policy = config.session_policy();
    tracing::info!(
        format = config.log.format.as_str(),
        filter = %config.log.default_filter,
        file = config.log.file.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_owned()),
        metrics = config.metrics_enabled,
        audit_retention_days = config.audit.retention_days,
        "observability configured"
    );
    if config.audit.retention_days == 0 {
        // Loud, because it is a deliberate choice with an unbounded consequence:
        // the audit table grows forever inside the same SQLite file that holds
        // custody, and nobody notices until the volume is full.
        tracing::warn!(
            "audit_retention_days = 0: the audit table will never be pruned. \
             This is a supported choice, but the store's growth is now unbounded."
        );
    }

    // Fails loudly here rather than at the first request: a base_url that would
    // silently downgrade every cookie is a configuration bug, not a runtime one.
    let http_config = HttpConfig::new(&config.base_url, &policy)?;

    // Two connections: one owned by the writer thread (all mutations), one
    // behind the read handle (keepalive + the internal lane). WAL journalling
    // is what lets those run concurrently without contending.
    let write_conn = store::open(&config.db_path, &config.keyfile_path)?;
    let read_conn = store::open(&config.db_path, &config.keyfile_path)?;
    tracing::info!(db = %config.db_path.display(), "store opened and migrated");

    let writer = Writer::spawn(write_conn);
    let writer_handle = writer.handle();
    let reader = Arc::new(Reader::new(read_conn));

    let audit = session_broker::audit::AuditSink::new(
        writer_handle.clone(),
        metrics.clone(),
        config.audit.clone(),
    );

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let now = clock.now();

    let sessions = Arc::new(SessionMap::with_durability(policy, writer_handle.clone()));
    let restored = rehydrate_sessions(&reader, &sessions);
    tracing::info!(sessions = restored, "sessions rehydrated");

    // Installed before anything can kill a session, so no death goes
    // unannounced. Purely a latency optimisation — the 401 on the next request
    // is still what enforces a revocation (INV-7).
    let events = SessionEvents::new();
    sessions.set_observer(events.clone());

    let oidc = Arc::new(OidcClient::discover(&config.oidc).await?);
    tracing::info!(
        issuer = config.oidc.issuer_url.as_deref().unwrap_or("<none>"),
        "OIDC discovery complete"
    );

    let (schedule_tx, schedule_rx) = tokio::sync::mpsc::unbounded_channel::<ScheduleRequest>();
    let custody_sink = CustodySink::new(writer_handle.clone(), schedule_tx);

    let upstream = Arc::new(OidcUpstream::new(
        oidc.clone(),
        reader.clone(),
        writer_handle.clone(),
        clock.clone(),
    ));
    let mut worker = KeepaliveWorker::new(
        KeepalivePolicy {
            // One policy decision spans both modules — a revoked upstream grant
            // has to mean the same thing to the worker and to the session map,
            // or sessions would outlive the grant they depend on (ADR-0011).
            on_upstream_revoked: policy.on_upstream_revoked,
            ..KeepalivePolicy::default()
        },
        sessions.clone(),
        clock.clone(),
        Arc::new(RandJitter),
        upstream,
    )
    .with_observability(metrics.clone(), Some(audit.clone()))
    .with_durability(writer_handle.clone());
    let scheduled = restore_keepalive_schedule(&reader, &mut worker, now);
    tracing::info!(custodies = scheduled, "keepalive schedule rebuilt");
    tokio::spawn(run_keepalive(worker, schedule_rx));

    let state = AppState {
        sessions: sessions.clone(),
        clock: clock.clone(),
        config: Arc::new(http_config),
        custody: Some(custody_sink),
        audit: Some(audit.clone()),
        metrics: metrics.clone(),
    };

    let internal_state = InternalState {
        sessions: sessions.clone(),
        reader: reader.clone(),
        clock: clock.clone(),
        api_key: config
            .broker_api_key
            .as_ref()
            .map(|k| Arc::from(k.expose())),
        writer: Some(writer_handle.clone()),
        last_touch: Default::default(),
        metrics: metrics.clone(),
        audit: Some(audit.clone()),
    };
    if internal_state.api_key.is_none() {
        tracing::warn!(
            "no broker_api_key configured: /internal/token will refuse every request, so \
             backend services cannot obtain upstream tokens on a user's behalf"
        );
    }

    let app = session_broker::telemetry::http::instrument_router(
        http::router(state)
            .layer(Extension(oidc))
            .layer(Extension(events.clone())),
        "public",
        metrics.clone(),
    );
    // The admin lane shares the internal listener: both are operator surfaces
    // that must not be internet-reachable, and giving them one bind address
    // means one firewall rule to get wrong instead of two.
    let admin_state = http::admin::AdminState {
        sessions: sessions.clone(),
        reader: reader.clone(),
        writer: writer_handle.clone(),
        clock: clock.clone(),
        admin_key: config.admin_api_key.as_ref().map(|k| Arc::from(k.expose())),
        audit: Some(audit.clone()),
        log: Some(log.clone()),
        metrics: metrics.clone(),
    };
    if admin_state.admin_key.is_none() {
        tracing::warn!(
            "no admin_api_key configured: /admin/* is disabled, so keys and sessions \
             cannot be managed from the console"
        );
    }
    // `/authz` shares the internal listener and the internal state: it is the
    // edge's per-request check, and the edge is a backend like any other.
    let mut internal_app = http::internal::router(internal_state.clone())
        .merge(http::authz::router(internal_state.clone()))
        .merge(http::admin::router(admin_state));
    if config.metrics_enabled {
        // On the internal listener, unauthenticated, next to the lanes the
        // network already has to protect (see `http::ops`).
        internal_app = internal_app.merge(
            axum::Router::new()
                .route("/metrics", axum::routing::get(http::ops::metrics))
                .with_state(internal_state)
                .layer(Extension(http::ops::OpsState {
                    metrics: metrics.clone(),
                    events: events.clone(),
                    log: Some(log.clone()),
                    audit: Some(audit.clone()),
                })),
        );
    }
    let internal_app = session_broker::telemetry::http::instrument_router(
        internal_app,
        "internal",
        metrics.clone(),
    );

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let internal_listener = tokio::net::TcpListener::bind(config.internal_bind_addr).await?;
    tracing::info!(
        addr = %config.bind_addr,
        internal_addr = %config.internal_bind_addr,
        base_url = %config.base_url,
        "session-broker listening"
    );

    // Two background timers, both cheap and both about the observability plane
    // keeping its own promises: the retention window is real, and a raised log
    // level comes back down on its own.
    tokio::spawn(run_audit_pruner(audit.clone(), clock.clone()));
    tokio::spawn(run_reaper(
        writer_handle.clone(),
        sessions.clone(),
        clock.clone(),
        config.reap_after_secs,
    ));
    tokio::spawn(run_log_override_expiry(log.clone(), clock.clone()));

    let public = tokio::spawn(async move { axum::serve(listener, app).await });
    let internal = tokio::spawn(async move { axum::serve(internal_listener, internal_app).await });

    // Either listener dying is fatal. A broker serving logins but not token
    // exchange (or the reverse) is half-broken in a way that looks healthy to
    // anything checking only one of them.
    tokio::select! {
        result = public => result??,
        result = internal => result??,
    }

    // Dropping the writer flushes and joins its thread, so a graceful exit does
    // not lose the last batch.
    drop(writer);
    Ok(())
}

/// The reaper (M6): drop what is provably dead, in memory and on disk.
///
/// Two halves that must both run. `SessionMap::sweep` frees the in-memory
/// entries — otherwise a long-running broker holds every session it has ever
/// issued — and the store command removes the durable rows. Neither is a
/// substitute for the other: memory is rebuilt from disk on restart, and disk
/// is never re-read while running.
async fn run_reaper(
    writer: session_broker::store::writer::WriterHandle,
    sessions: Arc<SessionMap>,
    clock: Arc<dyn Clock>,
    reap_after_secs: u64,
) {
    if reap_after_secs == 0 {
        // Loud, because the consequence is unbounded and silent: the session and
        // generation tables are the largest in the file, and every dead session
        // pins a custody row holding an encrypted refresh token.
        tracing::warn!(
            target: "broker::reaper",
            "reap_after_secs = 0: dead session rows are never removed and the store grows without bound"
        );
        return;
    }
    loop {
        let now = clock.now();
        let (dropped_sessions, retired_gens) = sessions.sweep(now);
        if dropped_sessions > 0 || retired_gens > 0 {
            tracing::debug!(
                target: "broker::reaper",
                dropped_sessions,
                retired_gens,
                "in-memory sweep"
            );
        }
        writer.enqueue(session_broker::store::writer::Command::Reap {
            dead_before: Timestamp(now.secs() - reap_after_secs as i64),
            txn_before: Timestamp(now.secs() - TXN_TTL_SECS as i64),
        });
        tokio::time::sleep(REAP_INTERVAL).await;
    }
}

/// Prune audit rows past the retention window (ADR-0015).
async fn run_audit_pruner(audit: session_broker::audit::AuditSink, clock: Arc<dyn Clock>) {
    loop {
        // Swept at boot as well as hourly: a broker that is restarted more often
        // than the interval would otherwise never prune at all.
        audit.prune(clock.now());
        tokio::time::sleep(AUDIT_PRUNE_INTERVAL).await;
    }
}

/// Restore the configured log filter once a temporary override falls due.
async fn run_log_override_expiry(
    log: Arc<session_broker::telemetry::LogControl>,
    clock: Arc<dyn Clock>,
) {
    loop {
        tokio::time::sleep(LOG_OVERRIDE_TICK).await;
        log.expire_due_override(clock.now().secs());
    }
}

/// Rebuild the in-memory session map from durable rows.
fn rehydrate_sessions(reader: &Reader, sessions: &SessionMap) -> usize {
    let loaded = reader.with(store::repo::rehydrate);
    let rows = match loaded {
        Ok(rows) => rows,
        // Booting with an empty map is survivable — everyone logs in again —
        // whereas refusing to boot leaves the service down entirely. Loud, not
        // fatal.
        Err(e) => {
            tracing::error!(error = %e, "could not rehydrate sessions; starting empty");
            return 0;
        }
    };

    let mut restored = 0;
    for entry in rows {
        let gens: Vec<Generation> = entry
            .generations
            .iter()
            .map(|g| Generation {
                gen_no: g.gen_no,
                token_hash: TokenHash::from_stored_bytes(g.token_hash),
                created_at: g.created_at,
                active_until: g.active_until,
                superseded_at: g.superseded_at,
            })
            .collect();

        if sessions.rehydrate_session(RestoredSession {
            sid: entry.session.sid.clone(),
            custody: entry.session.custody_id.clone(),
            sub: entry.session.sub.clone(),
            current_gen: entry.session.current_gen,
            idle_exp: entry.session.idle_exp,
            absolute_exp: entry.session.absolute_exp,
            gens,
        }) {
            restored += 1;
        }
    }
    restored
}

/// Rebuild the keepalive heap from `custody_sched` (§5).
///
/// Anything already overdue is spread across a 30-second window rather than
/// fired at once: after an outage every custody in the fleet is overdue
/// simultaneously, and a synchronous stampede is how a recovering deployment
/// turns itself into a rate-limited one.
fn restore_keepalive_schedule<U: session_broker::keepalive::Upstream>(
    reader: &Reader,
    worker: &mut KeepaliveWorker<U>,
    now: Timestamp,
) -> usize {
    const STAMPEDE_SPREAD_SECS: u64 = 30;

    let loaded = reader.with(store::repo::live_custody_schedules);
    let rows = match loaded {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "could not rebuild the keepalive schedule");
            return 0;
        }
    };

    let count = rows.len();
    let scheduler = worker.scheduler_mut();
    for (index, row) in rows.into_iter().enumerate() {
        let next_refresh = if row.next_refresh.secs() <= now.secs() {
            let spread = (index as u64 * STAMPEDE_SPREAD_SECS) / (count as u64).max(1);
            now.plus_secs(spread)
        } else {
            row.next_refresh
        };
        scheduler.insert_restored(row.custody_id, row.status, row.access_exp, next_refresh);
    }
    count
}

/// The worker's sleep loop: accept newly created custodies, and tick whenever
/// something is due.
async fn run_keepalive<U: session_broker::keepalive::Upstream>(
    mut worker: KeepaliveWorker<U>,
    mut schedule_rx: tokio::sync::mpsc::UnboundedReceiver<ScheduleRequest>,
) {
    loop {
        tokio::select! {
            incoming = schedule_rx.recv() => match incoming {
                Some(request) => {
                    worker.scheduler_mut().insert(
                        request.custody,
                        request.issued_at,
                        request.lifetime_secs,
                        &RandJitter,
                    );
                }
                // Every sink has been dropped, which only happens at shutdown.
                None => return,
            },
            _ = tokio::time::sleep(KEEPALIVE_IDLE_TICK) => {
                let handled = worker.tick().await;
                if handled > 0 {
                    tracing::debug!(handled, "keepalive refreshed custodies");
                }
            }
        }
    }
}
