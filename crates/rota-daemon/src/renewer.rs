//! Renewal pipeline driver.
//!
//! Walks one cert through the full CSR generate, CA submit, DCV
//! publish, await issuance, install, DCV remove sequence. Each step
//! emits an audit event so the dashboard can show progress and the
//! operator can grep when something goes sideways. The DCV TXT
//! record is removed in a `defer`-style cleanup even when issuance
//! fails, so a partial run doesn't leave stray records on the
//! domain.
//!
//! The driver is sync-async-mixed by design: rcgen runs synchronously
//! on the calling thread (key derivation is fast, no need to push it
//! to a blocking pool), file I/O for the persistent private key
//! goes through tokio::fs.

use std::path::Path;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rota_core::Result;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::audit::{AuditStore, EventKind, RenewalId, RenewalStatus};
use crate::backends::CertBackends;

const KEY_FILE_MODE: u32 = 0o600;

/// Drives one cert's renewal through every backend step.
pub struct CertRenewer {
  audit: Arc<dyn AuditStore>,
}

impl CertRenewer {
  pub fn new(audit: Arc<dyn AuditStore>) -> Self {
    Self { audit }
  }

  /// Run the full pipeline for one cert. Records start, every
  /// pipeline step, and a terminal status (success/failed) in the
  /// audit log.
  pub async fn run(&self, bundle: &CertBackends) -> Result<()> {
    let renewal_id = self.audit.start_renewal(&bundle.config.id).await?;
    info!(cert = %bundle.config.id, renewal_id = %renewal_id.as_str(), "renewal started");

    match self.run_pipeline(bundle, &renewal_id).await {
      Ok(()) => {
        self
          .audit
          .complete_renewal(&renewal_id, RenewalStatus::Success, None)
          .await?;
        info!(cert = %bundle.config.id, renewal_id = %renewal_id.as_str(), "renewal succeeded");
        Ok(())
      }
      Err(err) => {
        let msg = err.to_string();
        let _ = self
          .audit
          .append_event(&renewal_id, EventKind::Error, Some(&msg))
          .await;
        let _ = self
          .audit
          .complete_renewal(&renewal_id, RenewalStatus::Failed, Some(&msg))
          .await;
        warn!(cert = %bundle.config.id, renewal_id = %renewal_id.as_str(), error = %msg, "renewal failed");
        Err(err)
      }
    }
  }

  async fn run_pipeline(&self, bundle: &CertBackends, renewal_id: &RenewalId) -> Result<()> {
    let private_key_pem = load_or_create_key(&bundle.config.key_path).await?;

    let csr_pem = generate_csr(&bundle.config.domains, &private_key_pem)?;
    self
      .audit
      .append_event(renewal_id, EventKind::CsrGenerated, None)
      .await?;

    let challenge = bundle.ca.submit(&bundle.config.domains, &csr_pem).await?;
    self
      .audit
      .append_event(
        renewal_id,
        EventKind::CaSubmitted,
        Some(&challenge.record_name),
      )
      .await?;

    bundle.registrar.publish_txt(&challenge).await?;
    self
      .audit
      .append_event(
        renewal_id,
        EventKind::DcvPublished,
        Some(&challenge.record_name),
      )
      .await?;

    // Await issuance, then unconditionally clean up the DCV record.
    // Done as separate let bindings so the cleanup runs whether the
    // CA succeeded or failed.
    let issuance = bundle.ca.await_issuance(&bundle.config.domains).await;

    match bundle.registrar.remove_txt(&challenge).await {
      Ok(()) => {
        let _ = self
          .audit
          .append_event(renewal_id, EventKind::DcvRemoved, None)
          .await;
      }
      Err(cleanup_err) => {
        // Cleanup failure is recorded but does not override an
        // earlier failure. If issuance succeeded we still surface
        // the cleanup error so the operator notices the stray TXT.
        let _ = self
          .audit
          .append_event(
            renewal_id,
            EventKind::Error,
            Some(&format!("dcv cleanup: {cleanup_err}")),
          )
          .await;
        if issuance.is_ok() {
          return Err(cleanup_err);
        }
      }
    }

    let issued = issuance?;
    self
      .audit
      .append_event(renewal_id, EventKind::CertIssued, None)
      .await?;

    if let Some(install) = &bundle.install {
      install
        .install(&issued, &private_key_pem, &bundle.config.domains)
        .await?;
      self
        .audit
        .append_event(renewal_id, EventKind::CertInstalled, None)
        .await?;
    }

    Ok(())
  }
}

/// Read the persistent private key, or generate one if the file does
/// not exist. New keys are P-256 ECDSA; rotating algorithms across
/// renewals would invalidate the cert pinning operators may rely on,
/// so once a key is on disk it stays.
async fn load_or_create_key(path: &Path) -> Result<String> {
  match fs::read_to_string(path).await {
    Ok(pem) => Ok(pem),
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      let key_pair = KeyPair::generate()
        .map_err(|e| rota_core::Error::Install(format!("generate keypair: {e}")))?;
      let pem = key_pair.serialize_pem();
      write_key(path, &pem).await?;
      Ok(pem)
    }
    Err(e) => Err(rota_core::Error::Install(format!(
      "read key {}: {e}",
      path.display()
    ))),
  }
}

async fn write_key(path: &Path, pem: &str) -> Result<()> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)
      .await
      .map_err(|e| rota_core::Error::Install(format!("key dir {}: {e}", parent.display())))?;
  }
  let mut f = fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .mode(KEY_FILE_MODE)
    .open(path)
    .await
    .map_err(|e| rota_core::Error::Install(format!("open key {}: {e}", path.display())))?;
  f.write_all(pem.as_bytes())
    .await
    .map_err(|e| rota_core::Error::Install(format!("write key: {e}")))?;
  f.sync_all()
    .await
    .map_err(|e| rota_core::Error::Install(format!("fsync key: {e}")))?;
  Ok(())
}

fn generate_csr(domains: &[String], private_key_pem: &str) -> Result<String> {
  let key_pair = KeyPair::from_pem(private_key_pem)
    .map_err(|e| rota_core::Error::Ca(format!("parse private key: {e}")))?;
  let mut params = CertificateParams::new(domains.to_vec())
    .map_err(|e| rota_core::Error::Ca(format!("certificate params: {e}")))?;
  params.distinguished_name = rcgen::DistinguishedName::new();
  if let Some(cn) = domains.first() {
    params
      .distinguished_name
      .push(rcgen::DnType::CommonName, cn.clone());
  }
  let csr = params
    .serialize_request(&key_pair)
    .map_err(|e| rota_core::Error::Ca(format!("serialize csr: {e}")))?;
  csr
    .pem()
    .map_err(|e| rota_core::Error::Ca(format!("csr pem: {e}")))
}

#[cfg(test)]
mod tests;
