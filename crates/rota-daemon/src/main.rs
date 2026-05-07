//! `rotad`: the rota daemon.
//!
//! Owns scheduling, audit history, CA/registrar/install dispatch.
//! CLI clients talk to it over a UNIX socket; the dashboard is served
//! at the configured `listen_addr`. Renewal pipeline wiring is staged
//! across PRs. Current build wires the audit DB and the renewer; the
//! scheduler loop, CLI socket, and dashboard land in follow-ups.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rota_core::config::RotaConfig;
use rota_daemon::audit::AuditStore;
use rota_daemon::backends;
use rota_daemon::renewer::CertRenewer;
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

  let audit = Arc::new(AuditStore::open(&config.daemon.database_path).await?);
  info!(
    db = %config.daemon.database_path.display(),
    "audit store ready"
  );

  let _renewer = CertRenewer::new(Arc::clone(&audit));

  // Next PR: drive `_renewer` from a scheduler loop that ticks every
  // `check_interval_seconds` and decides which bundles in `bundles`
  // are within `renew_threshold_days` of expiry. Then bind the CLI
  // socket and the dashboard HTTP listener.
  drop(bundles);
  Ok(())
}
