//! Thin binary wrapper over the `mock_idp` library: parse CLI/env config,
//! spawn the server, run until Ctrl-C.

use clap::Parser;
use mock_idp::{config::Cli, spawn_mock_idp, MockIdpConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config: MockIdpConfig = Cli::parse().into();
    let handle = spawn_mock_idp(config).await?;

    tracing::info!(base_url = handle.base_url(), "mock-idp listening");

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    handle.shutdown().await;
    Ok(())
}
