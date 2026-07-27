//! An in-process, fully controllable mock OpenID Connect provider.
//!
//! This exists purely as a **test fixture** for `session-broker`: the
//! broker's OAuth2/OIDC flows (authorize → token, refresh, revoke,
//! userinfo) need to be developed and tested offline, deterministically,
//! and with direct hooks into the failure modes that are hard to provoke
//! against a real IdP — token expiry, upstream refresh failure, and
//! revocation. It is not, and must never become, a real identity provider:
//! there is no login UI, no password storage, no consent screen, and no
//! attempt at spec completeness beyond what the broker needs to exercise.
//!
//! Two ways to run it:
//! - as a binary (`cargo run -p mock-idp`), a thin wrapper over this
//!   library's [`spawn_mock_idp`] that binds a fixed port so its URL is
//!   stable across restarts;
//! - in-process from an integration test, via [`spawn_mock_idp`] directly,
//!   which binds an ephemeral port and hands back a [`MockIdpHandle`].
//!
//! See the `/__test__/*` routes (in the private `routes` module) for the
//! control surface: `POST /__test__/config`, `/expire`, `/revoke-refresh`,
//! `/fail-next`, and `GET /__test__/state`.

pub mod config;
mod error;
mod keys;
mod routes;
mod state;

use std::net::SocketAddr;

use anyhow::Context;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

pub use config::{Cli, ClientConfig, MockIdpConfig, UserConfig};

/// A running mock IdP instance.
///
/// Dropping the handle without calling [`MockIdpHandle::shutdown`] aborts
/// the server task as a safety net — tests that forget to shut down
/// explicitly still don't leak a bound listener past the test process — but
/// [`shutdown`](MockIdpHandle::shutdown) is the recommended, graceful path.
pub struct MockIdpHandle {
    base_url: String,
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<()>>,
}

impl MockIdpHandle {
    /// Base URL the server is listening on, e.g. `http://127.0.0.1:54321`.
    /// This is also the `issuer` in the discovery document and every
    /// signed `id_token`.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting new connections, let in-flight requests drain, and
    /// wait for the server task to exit. Safe to call at most once (it
    /// consumes the handle); [`Drop`] covers callers that don't.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for MockIdpHandle {
    fn drop(&mut self) {
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
    }
}

/// Start a mock IdP bound to `config.bind_addr` (port `0` binds an
/// ephemeral port — what integration tests should use) and return a handle
/// exposing the resolved base URL and a shutdown path.
///
/// The `issuer` used in the discovery document and every signed `id_token`
/// is derived from the address the server actually bound to, so the same
/// config produces a correct issuer whether the caller asked for a fixed
/// port or an ephemeral one.
pub async fn spawn_mock_idp(config: MockIdpConfig) -> anyhow::Result<MockIdpHandle> {
    tracing::warn!(
        "mock-idp is a TEST FIXTURE: no login UI, no real authentication, in-memory keys and \
         tokens, and a /__test__ control API that can forge session state — it must never be \
         deployed or exposed outside a test/dev environment"
    );

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("binding mock-idp to {}", config.bind_addr))?;
    let local_addr = listener
        .local_addr()
        .context("resolving mock-idp's bound address")?;
    let base_url = format!("http://{local_addr}");

    let state = state::AppState::new(config, base_url.clone())?;
    let app = routes::router(state);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
        if let Err(error) = result {
            tracing::error!(%error, "mock-idp server task exited with an error");
        }
    });

    Ok(MockIdpHandle {
        base_url,
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        server_task: Some(server_task),
    })
}
