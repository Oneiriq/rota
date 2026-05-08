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
use rota_core::cluster::ClusterCoordinator;
use rota_core::config::{AuditSpec, RotaConfig};
use rota_daemon::audit::{AuditStore, SqliteAuditStore};
use rota_daemon::backends;
use rota_daemon::cluster::NoOpCoordinator;
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

  let bundles = backends::build_from_config(&config).await?;
  for bundle in &bundles {
    info!(
      cert = %bundle.config.id,
      ca = %bundle.ca.name(),
      dcv = %bundle.dcv.name(),
      install = bundle.install.as_ref().map(|i| i.name()).unwrap_or("(stub)"),
      "cert backends bound"
    );
  }

  let alerts = backends::build_alerts(&config.alerts)?;
  for alert in &alerts {
    info!(backend = %alert.name(), "alert sink bound");
  }
  let alerts = Arc::new(alerts);

  let audit = build_audit(&config).await?;
  info!(backend = %audit.name(), "audit store ready");

  let cluster = build_cluster(&config)?;
  info!(
    coordinator = %cluster.name(),
    node = %cluster.node_id(),
    "cluster coordinator bound"
  );

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
  )
  .with_alerts(Arc::clone(&alerts))
  .with_cluster(Arc::clone(&cluster));

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
  let cluster_task = {
    let cluster = Arc::clone(&cluster);
    tokio::spawn(async move {
      if let Err(err) = cluster.run().await {
        tracing::error!(error = %err, "cluster coordinator failed");
      }
    })
  };

  // Any task returning is unexpected (all four should loop
  // forever). When one returns, log and exit; the supervisor
  // (systemd, Container Manager) restarts the daemon.
  tokio::select! {
    _ = scheduler_task => tracing::warn!("scheduler task exited"),
    _ = socket_task => tracing::warn!("socket task exited"),
    _ = dashboard_task => tracing::warn!("dashboard task exited"),
    _ = cluster_task => tracing::warn!("cluster coordinator task exited"),
  }
  Ok(())
}

/// Construct the cluster coordinator from config. This PR ships only
/// the NoOp coordinator (single-node, always leader); the SurrealDB
/// coordinator that drives real federation lands alongside cert
/// distribution in the follow-up PR. We still parse `cluster.enabled`
/// here so operators get a clear "not yet implemented" error instead
/// of silent single-node behaviour when their config requested a
/// cluster.
fn build_cluster(config: &RotaConfig) -> Result<Arc<dyn ClusterCoordinator>> {
  match &config.cluster {
    None => Ok(Arc::new(NoOpCoordinator::new("local".to_owned()))),
    Some(spec) if !spec.enabled => Ok(Arc::new(NoOpCoordinator::new(spec.node_id.clone()))),
    Some(spec) => Err(anyhow::anyhow!(
      "cluster.enabled = true (node_id = {}) but this build does not yet ship a clustering coordinator; \
       upgrade to a build that lands cert distribution to followers",
      spec.node_id,
    )),
  }
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
