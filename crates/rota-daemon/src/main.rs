//! `rotad`: the rota daemon.
//!
//! Owns scheduling, audit history, CA/registrar/install dispatch.
//! CLI clients talk to it over a UNIX socket; the dashboard is served
//! at the configured `listen_addr`. Renewal pipeline wiring is staged
//! across PRs. Current build wires the audit DB and the renewer; the
//! scheduler loop, CLI socket, and dashboard land in follow-ups.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use rota_core::config::{AuditSpec, RotaConfig};
use rota_daemon::audit::{AuditStore, SqliteAuditStore};
use rota_daemon::backends;
use rota_daemon::dashboard::{self, DashboardState};
use rota_daemon::renewer::CertRenewer;
use rota_daemon::scheduler::{Scheduler, SchedulerConfig};
use rota_daemon::socket::SocketServer;
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

  let audit = build_audit(&config).await?;
  info!(backend = %audit.name(), "audit store ready");

  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let bundles = Arc::new(bundles);

  let interval = Duration::from_secs(config.daemon.check_interval_seconds);
  let scheduler = Scheduler::new(
    Arc::clone(&bundles),
    Arc::clone(&renewer),
    SchedulerConfig {
      check_interval: interval,
      threshold_days: config.daemon.renew_threshold_days as i64,
      // Failure cooldown matches the natural sweep cadence: a
      // failed renewal will not retry until the next interval has
      // elapsed. v0.2 can swap in exponential backoff if it shows
      // up as a real-world problem.
      failure_cooldown: interval,
    },
  );

  let socket_server = SocketServer::new(
    Arc::clone(&bundles),
    Arc::clone(&audit),
    Arc::clone(&renewer),
  );
  let socket_path = config.daemon.socket_path.clone();

  let dashboard_state = DashboardState {
    bundles: Arc::clone(&bundles),
    audit: Arc::clone(&audit),
    renewer: Arc::clone(&renewer),
  };
  let dashboard_addr = config.daemon.listen_addr.clone();

  let scheduler_task = tokio::spawn(scheduler.run());
  let socket_task = tokio::spawn(async move {
    if let Err(err) = socket_server.serve(socket_path).await {
      tracing::error!(error = %err, "control socket failed");
    }
  });
  let dashboard_task = tokio::spawn(async move {
    if let Err(err) = dashboard::serve(dashboard_state, &dashboard_addr).await {
      tracing::error!(error = %err, "dashboard failed");
    }
  });

  // Any task returning is unexpected (all three should loop
  // forever). When one returns, log and exit; the supervisor
  // (systemd, Container Manager) restarts the daemon.
  tokio::select! {
    _ = scheduler_task => tracing::warn!("scheduler task exited"),
    _ = socket_task => tracing::warn!("socket task exited"),
    _ = dashboard_task => tracing::warn!("dashboard task exited"),
  }
  Ok(())
}

async fn build_audit(config: &RotaConfig) -> Result<Arc<dyn AuditStore>> {
  match &config.audit {
    None => {
      let store = SqliteAuditStore::open(&config.daemon.database_path).await?;
      Ok(Arc::new(store))
    }
    Some(AuditSpec::Sqlite { path }) => {
      let path = path.clone().unwrap_or_else(|| config.daemon.database_path.clone());
      let store = SqliteAuditStore::open(&path).await?;
      Ok(Arc::new(store))
    }
    #[cfg(feature = "surrealdb")]
    Some(AuditSpec::Surrealdb { .. }) => {
      let store = rota_daemon::audit::SurrealAuditStore::from_spec(
        config.audit.as_ref().expect("matched Surrealdb above"),
      )
      .await?;
      Ok(Arc::new(store))
    }
    #[cfg(not(feature = "surrealdb"))]
    Some(AuditSpec::Surrealdb { .. }) => Err(anyhow::anyhow!(
      "config selects surrealdb audit backend but rota-daemon was built without the `surrealdb` feature"
    )),
  }
}
