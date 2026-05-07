//! `rotad` — the rota daemon.
//!
//! Owns scheduling, audit history, CA/registrar/install dispatch.
//! CLI clients talk to it over a UNIX socket; the dashboard is served
//! at the configured `listen_addr`. v0.0.0 is a load-bearing scaffold:
//! the wiring is in place but renewals themselves are stubbed.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rota_core::config::RotaConfig;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "rotad", about = "rota daemon", version)]
struct Args {
  /// Path to rota.yaml.
  #[arg(short, long, env = "ROTA_CONFIG", default_value = "/etc/rota/rota.yaml")]
  config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
    .init();

  let args = Args::parse();
  let config = RotaConfig::load(&args.config)?;
  info!(
    cert_count = config.certs.len(),
    listen = %config.daemon.listen_addr,
    "rotad starting"
  );

  // v0.1: spawn scheduler loop, bind UNIX socket for CLI, bind HTTP
  // for dashboard, attach SQLite audit DB. The trait surface in
  // rota-core::backend drives all of it.
  Ok(())
}
