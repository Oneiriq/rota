//! Periodic renewal scheduler.
//!
//! Ticks every `check_interval`, walks every bundle the daemon was
//! configured with, and decides whether each one is within its
//! renewal window. The decision rule is intentionally simple:
//!
//!   - No install backend -> skip (nothing to read).
//!   - Install backend reports `Ok(None)` (never installed, or the
//!     backend can't read back) -> renew.
//!   - Cert parses and `not_after - now < threshold_days` -> renew.
//!   - Cert parses and is comfortably ahead of the threshold -> wait.
//!
//! Failed renewals enter a per-cert cooldown so a flaky CA doesn't
//! get hammered on every tick. The cooldown is fixed at one
//! `check_interval` for v0.1; exponential backoff can layer in
//! later if it turns out to matter.
//!
//! The scheduler does not spawn a task per cert; it walks them
//! sequentially within one tick. Renewals are infrequent (worst
//! case 47 days out, typically much longer), and serialising them
//! keeps the audit log linear and the rate limits at the CA / DNS
//! provider undisturbed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rota_core::backend::{AlertBackend, AlertEvent, AlertKind};
use rota_core::cert::parse_not_after;
use rota_core::cluster::ClusterCoordinator;
use rota_core::secrets::redact;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::audit::RenewalStatus;
use crate::backends::CertBackends;
use crate::cluster::NoOpCoordinator;
use crate::metrics;
use crate::renewer::CertRenewer;

/// Knobs the scheduler reads. Built from `config::DaemonConfig` in
/// the daemon's bootstrap.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
  pub check_interval: Duration,
  pub threshold_days: i64,
  pub failure_cooldown: Duration,
}

#[derive(Debug, Default, Clone)]
struct CertState {
  last_attempt_at: Option<DateTime<Utc>>,
  last_outcome: Option<RenewalStatus>,
  consecutive_failures: u32,
}

pub struct Scheduler {
  bundles: Arc<Vec<CertBackends>>,
  renewer: Arc<CertRenewer>,
  alerts: Arc<Vec<Arc<dyn AlertBackend>>>,
  cluster: Arc<dyn ClusterCoordinator>,
  config: SchedulerConfig,
  state: Arc<Mutex<HashMap<String, CertState>>>,
}

impl Scheduler {
  pub fn new(
    bundles: Arc<Vec<CertBackends>>,
    renewer: Arc<CertRenewer>,
    config: SchedulerConfig,
  ) -> Self {
    Self {
      bundles,
      renewer,
      alerts: Arc::new(Vec::new()),
      cluster: Arc::new(NoOpCoordinator::new("local".to_owned())),
      config,
      state: Arc::new(Mutex::new(HashMap::new())),
    }
  }

  /// Attach a list of alert sinks. Every renewal failure dispatches
  /// to every entry. Builder-style so existing call sites that don't
  /// configure alerts keep working unchanged.
  pub fn with_alerts(mut self, alerts: Arc<Vec<Arc<dyn AlertBackend>>>) -> Self {
    self.alerts = alerts;
    self
  }

  /// Attach a cluster coordinator. The scheduler skips its sweep on
  /// any tick where the coordinator reports follower mode. Builder-
  /// style so single-node call sites keep working unchanged
  /// (defaults to a NoOpCoordinator that always reports leader).
  pub fn with_cluster(mut self, cluster: Arc<dyn ClusterCoordinator>) -> Self {
    self.cluster = cluster;
    self
  }

  /// Long-running loop. Returns only on shutdown.
  pub async fn run(self) {
    info!(
      bundles = self.bundles.len(),
      interval_s = self.config.check_interval.as_secs(),
      threshold_days = self.config.threshold_days,
      "scheduler started"
    );
    let mut ticker = tokio::time::interval(self.config.check_interval);
    // Skip the immediate-fire that interval emits at t=0 so we don't
    // hammer every CA on daemon startup. The first sweep happens
    // after one full interval.
    ticker.tick().await;
    loop {
      ticker.tick().await;
      self.sweep().await;
    }
  }

  /// Single sweep over every bundle. Public for the future
  /// `rota renew` CLI hook. Followers (cluster mode, lock not held)
  /// skip the sweep silently; the leader keeps doing the work.
  pub async fn sweep(&self) {
    if !self.cluster.is_leader() {
      tracing::debug!(
        coordinator = %self.cluster.name(),
        node = %self.cluster.node_id(),
        "scheduler sweep skipped: follower mode"
      );
      return;
    }
    for bundle in self.bundles.iter() {
      if self.should_renew(bundle).await {
        self.attempt_renewal(bundle).await;
      }
    }
  }

  async fn should_renew(&self, bundle: &CertBackends) -> bool {
    // Cooldown gate first: if the last attempt failed within
    // failure_cooldown, leave it alone. Cheap to evaluate and means
    // the rest of this method doesn't need to worry about flapping.
    if self.in_cooldown(&bundle.config.id).await {
      return false;
    }

    let Some(install) = bundle.install.as_ref() else {
      return false;
    };

    match install.current_cert_pem(&bundle.config.id).await {
      Ok(None) => {
        // Never installed (or the backend doesn't introspect).
        // Trigger so the renewer establishes a baseline.
        true
      }
      Ok(Some(pem)) => match parse_not_after(&pem) {
        Ok(not_after) => {
          let delta = not_after - Utc::now();
          let days_left = delta.num_days();
          // Gauge tracks fractional days so a cert that expires in
          // 12 hours shows up as 0.5 rather than rounding to 0.
          let days_left_f = (delta.num_seconds() as f64) / 86_400.0;
          metrics::set_days_until_expiry(&bundle.config.id, days_left_f);
          let due = days_left <= self.config.threshold_days;
          if !due {
            tracing::debug!(
              cert = %bundle.config.id,
              days_left,
              "cert not yet due"
            );
          }
          due
        }
        Err(err) => {
          // Unparseable installed cert is a recoverable case: log,
          // treat as due, and let the renewer overwrite it.
          warn!(
            cert = %bundle.config.id,
            error = %err,
            "installed cert did not parse; renewing"
          );
          true
        }
      },
      Err(err) => {
        // Hard read failure: skip this cycle so a transient FS or
        // DSM hiccup doesn't trigger an unnecessary renewal.
        warn!(
          cert = %bundle.config.id,
          error = %err,
          "current_cert_pem failed; skipping this cycle"
        );
        false
      }
    }
  }

  async fn in_cooldown(&self, cert_id: &str) -> bool {
    let state = self.state.lock().await;
    let Some(s) = state.get(cert_id) else {
      return false;
    };
    let (Some(last), Some(RenewalStatus::Failed)) = (s.last_attempt_at, s.last_outcome) else {
      return false;
    };
    let elapsed = Utc::now() - last;
    let cooldown = chrono::Duration::from_std(self.config.failure_cooldown)
      .unwrap_or(chrono::Duration::seconds(0));
    elapsed < cooldown
  }

  async fn attempt_renewal(&self, bundle: &CertBackends) {
    let result = self.renewer.run(bundle).await;
    let failure_msg = match &result {
      Ok(()) => None,
      Err(err) => Some(redact(&err.to_string())),
    };

    {
      let mut state = self.state.lock().await;
      let s = state.entry(bundle.config.id.clone()).or_default();
      s.last_attempt_at = Some(Utc::now());
      if result.is_ok() {
        s.last_outcome = Some(RenewalStatus::Success);
        s.consecutive_failures = 0;
      } else {
        s.last_outcome = Some(RenewalStatus::Failed);
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
      }
    }

    let outcome = if result.is_ok() {
      metrics::OUTCOME_SUCCESS
    } else {
      metrics::OUTCOME_FAILURE
    };
    metrics::record_renewal_attempt(&bundle.config.id, outcome);

    if let Some(msg) = failure_msg {
      self.dispatch_failure(&bundle.config.id, &msg).await;
    }
  }

  /// Fan a `RenewalFailed` event out to every configured alert sink.
  /// Per-sink errors are logged but do not propagate; a flaky alert
  /// backend cannot be allowed to break the renewal pipeline outcome.
  async fn dispatch_failure(&self, cert_id: &str, message: &str) {
    if self.alerts.is_empty() {
      return;
    }
    let event = AlertEvent {
      cert_id: cert_id.to_owned(),
      kind: AlertKind::RenewalFailed,
      message: message.to_owned(),
      timestamp: Utc::now(),
    };
    for alert in self.alerts.iter() {
      let outcome = match alert.dispatch(&event).await {
        Ok(()) => metrics::OUTCOME_SUCCESS,
        Err(err) => {
          tracing::error!(
            backend = %alert.name(),
            cert = %cert_id,
            error = %err,
            "alert dispatch failed"
          );
          metrics::OUTCOME_FAILURE
        }
      };
      metrics::record_alert_dispatch(alert.name(), outcome);
    }
  }
}

#[cfg(test)]
mod tests;
