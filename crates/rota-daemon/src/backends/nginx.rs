//! Filesystem write plus an nginx reload subprocess.
//!
//! Wraps [`FilesystemInstall`] for the actual file landing (so the
//! atomic-rename + correct-mode behavior is shared with the bare
//! filesystem backend), then runs a configurable reload command so
//! nginx actually serves the new cert. The default reload is
//! `nginx -s reload`; operators on systemd typically override with
//! `systemctl reload nginx`, and a sudoers rule keeps the daemon
//! itself unprivileged.
//!
//! The reload runs without a shell wrapper, so argv entries are not
//! interpreted (no globbing, no env interpolation). A non-zero exit
//! is surfaced as an `Install` error: rota would rather fail loud
//! than serve a stale cert behind a "successful" install.

use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use rota_core::backend::{InstallBackend, IssuedCert};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use tokio::process::Command;
use tracing::{info, warn};

use super::filesystem::FilesystemInstall;

/// Default reload invocation when none is configured.
const DEFAULT_RELOAD: &[&str] = &["nginx", "-s", "reload"];

#[derive(Debug, Clone)]
pub struct NginxInstall {
  filesystem: FilesystemInstall,
  reload_command: Vec<String>,
}

impl NginxInstall {
  pub fn new(directory: PathBuf, cert_id: String, reload_command: Option<Vec<String>>) -> Self {
    let reload_command = reload_command.filter(|c| !c.is_empty()).unwrap_or_else(|| {
      DEFAULT_RELOAD
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<_>>()
    });
    Self {
      filesystem: FilesystemInstall::new(directory, cert_id),
      reload_command,
    }
  }

  async fn run_reload(&self) -> Result<()> {
    let (program, args) = self
      .reload_command
      .split_first()
      .expect("reload_command always has at least one entry");
    let output = Command::new(program)
      .args(args)
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .output()
      .await
      .map_err(|e| {
        Error::Install(format!(
          "spawn nginx reload {program}: {}",
          redact(&e.to_string())
        ))
      })?;

    if !output.status.success() {
      let stderr = String::from_utf8_lossy(&output.stderr);
      let stdout = String::from_utf8_lossy(&output.stdout);
      let combined = format!("stderr: {stderr}\nstdout: {stdout}");
      return Err(Error::Install(format!(
        "nginx reload {program} exited {}: {}",
        output
          .status
          .code()
          .map(|c| c.to_string())
          .unwrap_or_else(|| "<signal>".into()),
        redact(combined.trim())
      )));
    }

    info!(program = %program, "nginx reload ok");
    Ok(())
  }
}

#[async_trait]
impl InstallBackend for NginxInstall {
  fn name(&self) -> &str {
    "nginx"
  }

  async fn install(
    &self,
    cert: &IssuedCert,
    private_key_pem: &str,
    domains: &[String],
  ) -> Result<()> {
    self
      .filesystem
      .install(cert, private_key_pem, domains)
      .await?;
    if let Err(err) = self.run_reload().await {
      // Files already landed; the operator needs to know reload
      // failed so they can investigate. Surface as Install error so
      // the renewer records it on the audit log.
      warn!(error = %err, "nginx reload failed after filesystem install");
      return Err(err);
    }
    Ok(())
  }

  async fn current_cert_pem(&self, cert_id: &str) -> Result<Option<String>> {
    self.filesystem.current_cert_pem(cert_id).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn issued_cert() -> IssuedCert {
    IssuedCert {
      cert_pem: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_owned(),
      chain_pem: "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n".to_owned(),
    }
  }

  #[tokio::test]
  async fn install_lands_files_when_reload_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let install = NginxInstall::new(
      tmp.path().to_owned(),
      "nginx-ok".to_owned(),
      Some(vec!["true".to_owned()]),
    );
    install
      .install(&issued_cert(), "PRIVKEY", &[])
      .await
      .unwrap();

    assert!(tmp.path().join("nginx-ok.crt").exists());
    assert!(tmp.path().join("nginx-ok.fullchain.crt").exists());
    assert!(tmp.path().join("nginx-ok.key").exists());
  }

  #[tokio::test]
  async fn install_errors_when_reload_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let install = NginxInstall::new(
      tmp.path().to_owned(),
      "nginx-fail".to_owned(),
      Some(vec!["false".to_owned()]),
    );
    let err = install
      .install(&issued_cert(), "PRIVKEY", &[])
      .await
      .expect_err("false exit must fail");
    assert!(err.to_string().contains("nginx reload"), "got: {err}");

    // Files DID land before reload was attempted; the operator can
    // still rerun reload manually after fixing the underlying issue.
    assert!(tmp.path().join("nginx-fail.crt").exists());
  }

  #[tokio::test]
  async fn empty_reload_command_falls_back_to_default() {
    let install = NginxInstall::new(
      PathBuf::from("/tmp/unused"),
      "fallback".to_owned(),
      Some(vec![]),
    );
    assert_eq!(install.reload_command, vec!["nginx", "-s", "reload"]);
  }

  #[tokio::test]
  async fn missing_reload_command_falls_back_to_default() {
    let install = NginxInstall::new(PathBuf::from("/tmp/unused"), "fallback".to_owned(), None);
    assert_eq!(install.reload_command, vec!["nginx", "-s", "reload"]);
  }

  #[tokio::test]
  async fn current_cert_pem_delegates_to_filesystem() {
    let tmp = tempfile::tempdir().unwrap();
    let install = NginxInstall::new(
      tmp.path().to_owned(),
      "delegated".to_owned(),
      Some(vec!["true".to_owned()]),
    );
    assert!(install
      .current_cert_pem("delegated")
      .await
      .unwrap()
      .is_none());
    install
      .install(&issued_cert(), "PRIVKEY", &[])
      .await
      .unwrap();
    let pem = install.current_cert_pem("delegated").await.unwrap();
    assert!(pem.unwrap().contains("LEAF"));
  }
}
