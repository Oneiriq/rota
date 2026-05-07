//! `rotad`: the rota daemon.
//!
//! Owns scheduling, audit history, CA/registrar/install dispatch.
//! CLI clients talk to it over a UNIX socket; the dashboard is served
//! at the configured `listen_addr`. Renewal pipeline wiring is staged
//! across PRs; v0.0.0 wired the trait surface, this build adds the
//! Namecheap CA + registrar implementations and the config-to-trait-
//! object dispatch the scheduler will drive.

mod backends;

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
  #[arg(
    short,
    long,
    env = "ROTA_CONFIG",
    default_value = "/etc/rota/rota.yaml"
  )]
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

  let bundles = backends::build_from_config(&config)?;
  for bundle in &bundles {
    info!(
      cert = %bundle.config.id,
      ca = %bundle.ca.name(),
      registrar = %bundle.registrar.name(),
      install = bundle.install.as_ref().map(|i| i.name()).unwrap_or("(stub)"),
      "cert backends bound"
    );
  }

  // v0.1: spawn scheduler loop, bind UNIX socket for CLI, bind HTTP
  // for dashboard, attach SQLite audit DB. The trait surface in
  // rota-core::backend drives all of it.
  Ok(())
}
