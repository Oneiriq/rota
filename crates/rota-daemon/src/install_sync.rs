//! Cluster install-sync task.
//!
//! Followers in a cluster poll the audit store for new
//! [`IssuedCertRecord`](crate::audit::IssuedCertRecord)s and run
//! their local [`InstallBackend`] when the audit's cert is newer
//! than what's on disk. The leader skips this work — the renewer
//! pipeline already handles install for the leader's local
//! install backend.
//!
//! Private key material is NOT distributed through the audit store.
//! Operators provision the same `key_path` private key on every
//! cluster member out-of-band (config-management, secrets manager,
//! whatever they use). This task reads the local key from
//! `cert.key_path` and pairs it with the audit's cert + chain.
//!
//! Cert freshness check: the task parses `notAfter` on both the
//! local cert (via `InstallBackend::current_cert_pem`) and the
//! audit's cert PEM. It installs only when the audit's `notAfter`
//! is strictly later, so an idle follower doesn't churn re-installs
//! every poll.

use std::sync::Arc;
use std::time::Duration;

use rota_core::backend::IssuedCert;
use rota_core::cert::parse_not_after;
use rota_core::cluster::ClusterCoordinator;
use rota_core::secrets::redact;
use tracing::{info, warn};

use crate::audit::AuditStore;
use crate::backends::CertBackends;

#[derive(Debug, Clone, Copy)]
pub struct InstallSyncConfig {
  pub poll_interval: Duration,
}

pub struct InstallSyncTask {
  bundles: Arc<Vec<CertBackends>>,
  audit: Arc<dyn AuditStore>,
  cluster: Arc<dyn ClusterCoordinator>,
  config: InstallSyncConfig,
}

impl InstallSyncTask {
  pub fn new(
    bundles: Arc<Vec<CertBackends>>,
    audit: Arc<dyn AuditStore>,
    cluster: Arc<dyn ClusterCoordinator>,
    config: InstallSyncConfig,
  ) -> Self {
    Self {
      bundles,
      audit,
      cluster,
      config,
    }
  }

  /// Long-running loop. Skip the immediate-fire from `interval`
  /// (matching the scheduler's pattern) so we don't double up with
  /// the renewer's own install on a fresh leader.
  pub async fn run(self) {
    info!(
      bundles = self.bundles.len(),
      poll_s = self.config.poll_interval.as_secs(),
      "install_sync task started"
    );
    let mut ticker = tokio::time::interval(self.config.poll_interval);
    ticker.tick().await;
    loop {
      ticker.tick().await;
      self.sweep().await;
    }
  }

  /// Single sweep over every bundle. Public so tests can drive it
  /// without spinning the timer loop.
  pub async fn sweep(&self) {
    if self.cluster.is_leader() {
      // Leader's renewer pipeline handles install for the leader's
      // local install backend; nothing to do here.
      return;
    }
    for bundle in self.bundles.iter() {
      self.maybe_install(bundle).await;
    }
  }

  async fn maybe_install(&self, bundle: &CertBackends) {
    let Some(install) = bundle.install.as_ref() else {
      return;
    };
    let cert_id = &bundle.config.id;

    let record = match self.audit.latest_issued_cert(cert_id).await {
      Ok(Some(r)) => r,
      Ok(None) => return,
      Err(err) => {
        warn!(cert = %cert_id, error = %err, "install_sync: latest_issued_cert failed");
        return;
      }
    };

    // Compare against what's already on disk via the install
    // backend's read-back path. If the local cert's notAfter is the
    // same as or later than the audit's, leave it alone — the audit
    // is just a copy of an issuance the leader already pushed.
    let audit_not_after = match parse_not_after(&record.cert_pem) {
      Ok(t) => t,
      Err(err) => {
        warn!(cert = %cert_id, error = %err, "install_sync: audit cert unparseable");
        return;
      }
    };
    if let Ok(Some(local_pem)) = install.current_cert_pem(cert_id).await {
      if let Ok(local_not_after) = parse_not_after(&local_pem) {
        if local_not_after >= audit_not_after {
          tracing::debug!(
            cert = %cert_id,
            "install_sync: local cert is current; skipping install"
          );
          return;
        }
      }
    }

    let private_key_pem = match tokio::fs::read_to_string(&bundle.config.key_path).await {
      Ok(k) => k,
      Err(err) => {
        warn!(
          cert = %cert_id,
          path = %bundle.config.key_path.display(),
          error = %redact(&err.to_string()),
          "install_sync: cannot read local private key; skipping"
        );
        return;
      }
    };

    let issued = IssuedCert {
      cert_pem: record.cert_pem,
      chain_pem: record.chain_pem,
    };
    match install
      .install(&issued, &private_key_pem, &bundle.config.domains)
      .await
    {
      Ok(()) => info!(
        cert = %cert_id,
        backend = %install.name(),
        "install_sync: follower installed cert from cluster audit"
      ),
      Err(err) => warn!(
        cert = %cert_id,
        backend = %install.name(),
        error = %err,
        "install_sync: follower install failed"
      ),
    }
  }
}

#[cfg(test)]
mod tests;
