//! Synology DSM install backend, via the on-box `synowebapi` binary.
//!
//! DSM exposes cert management through `SYNO.Core.Certificate`. The
//! flow rota uses:
//!
//! 1. List existing certs → look for one whose description matches our
//!    configured `description`. If found, capture its id so the import
//!    happens as an update rather than a new entry.
//! 2. Stage cert / chain / private key into a temp directory the DSM
//!    user has read access to.
//! 3. Invoke `synowebapi --exec api=SYNO.Core.Certificate method=import`
//!    with the staged paths and the optional id. DSM reloads its nginx
//!    automatically as part of the import.
//!
//! `synowebapi` only exists on a running DSM box so the binary call
//! itself is exercised on real hardware, not in CI. The dispatch
//! logic, JSON parsing, and command construction are unit-tested in
//! isolation here.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use rota_core::backend::{InstallBackend, IssuedCert};
use rota_core::{Error, Result};
use serde::Deserialize;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info};

const SYNOWEBAPI: &str = "synowebapi";
const CERT_API: &str = "SYNO.Core.Certificate";
const CRT_MODE: u32 = 0o644;
const KEY_MODE: u32 = 0o600;

#[derive(Debug, Clone)]
pub struct DsmInstall {
  description: String,
  /// Override the staging directory. Defaults to a fresh tempdir per
  /// install. Tests inject a path so they can assert on the staged
  /// files without invoking the real `synowebapi`.
  staging_root: Option<PathBuf>,
  /// Override the binary path. Tests use this to point at a stub.
  binary: String,
}

impl DsmInstall {
  pub fn new(description: String) -> Self {
    Self {
      description,
      staging_root: None,
      binary: SYNOWEBAPI.to_owned(),
    }
  }

  /// Stage cert artifacts to disk. Public so on-host integration
  /// tests can drive it directly; the daemon path goes through
  /// `install`.
  pub async fn stage(
    &self,
    cert: &IssuedCert,
    private_key_pem: &str,
    dir: &Path,
  ) -> Result<StagedPaths> {
    fs::create_dir_all(dir)
      .await
      .map_err(|e| Error::Install(format!("create staging {}: {e}", dir.display())))?;

    let cert_path = dir.join("cert.crt");
    let chain_path = dir.join("chain.crt");
    let key_path = dir.join("key.key");

    write_file(&cert_path, cert.cert_pem.as_bytes(), CRT_MODE).await?;
    write_file(&chain_path, cert.chain_pem.as_bytes(), CRT_MODE).await?;
    write_file(&key_path, private_key_pem.as_bytes(), KEY_MODE).await?;

    Ok(StagedPaths {
      cert_path,
      chain_path,
      key_path,
    })
  }
}

#[async_trait]
impl InstallBackend for DsmInstall {
  fn name(&self) -> &str {
    "dsm"
  }

  async fn install(
    &self,
    cert: &IssuedCert,
    private_key_pem: &str,
    _domains: &[String],
  ) -> Result<()> {
    let temp = match &self.staging_root {
      Some(root) => StagingDir::Borrowed(root.clone()),
      None => {
        StagingDir::Owned(tempfile::tempdir().map_err(|e| Error::Install(format!("tempdir: {e}")))?)
      }
    };
    let staged = self.stage(cert, private_key_pem, temp.path()).await?;

    let existing_id = self.find_existing_id().await?;
    self.run_import(&staged, existing_id.as_deref()).await?;

    info!(
      description = %self.description,
      existing_id = ?existing_id,
      "dsm certificate imported"
    );
    Ok(())
  }
}

impl DsmInstall {
  async fn find_existing_id(&self) -> Result<Option<String>> {
    let output = run_synowebapi(
      &self.binary,
      &[
        format!("api={CERT_API}"),
        "method=list".to_owned(),
        "version=1".to_owned(),
      ],
    )
    .await?;

    let parsed: ListResponse = serde_json::from_slice(&output)
      .map_err(|e| Error::Install(format!("parse synowebapi list output: {e}")))?;
    if !parsed.success {
      return Err(Error::Install(
        "synowebapi list returned success=false".into(),
      ));
    }
    Ok(
      parsed
        .data
        .certificates
        .into_iter()
        .find(|c| c.desc == self.description)
        .map(|c| c.id),
    )
  }

  async fn run_import(&self, staged: &StagedPaths, existing_id: Option<&str>) -> Result<()> {
    // `Command::args` passes each entry as a distinct argv slot, so
    // synowebapi receives the description verbatim. Skip the manual
    // `\"...\"` wrapping the prior version had; that was at best
    // redundant and at worst broke when the operator put a `"`
    // inside their description.
    let mut args = vec![
      format!("api={CERT_API}"),
      "method=import".to_owned(),
      "version=1".to_owned(),
      format!("desc={}", self.description),
      format!("cert={}", staged.cert_path.display()),
      format!("inter_cert={}", staged.chain_path.display()),
      format!("key={}", staged.key_path.display()),
      "as_default=true".to_owned(),
    ];
    if let Some(id) = existing_id {
      args.push(format!("id={id}"));
    }

    let output = run_synowebapi(&self.binary, &args).await?;

    let parsed: ImportResponse = serde_json::from_slice(&output)
      .map_err(|e| Error::Install(format!("parse synowebapi import output: {e}")))?;
    if !parsed.success {
      return Err(Error::Install(format!(
        "synowebapi import returned success=false: {:?}",
        parsed.error
      )));
    }
    Ok(())
  }
}

async fn run_synowebapi(binary: &str, args: &[String]) -> Result<Vec<u8>> {
  debug!(binary, ?args, "invoking synowebapi");
  let output = Command::new(binary)
    .arg("--exec")
    .args(args)
    .output()
    .await
    .map_err(|e| Error::Install(format!("spawn {binary}: {e}")))?;
  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr);
    return Err(Error::Install(format!(
      "{binary} exited {}: {}",
      output.status, stderr
    )));
  }
  Ok(output.stdout)
}

async fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
  let mut file = fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .mode(mode)
    .open(path)
    .await
    .map_err(|e| Error::Install(format!("open {}: {e}", path.display())))?;
  file
    .write_all(contents)
    .await
    .map_err(|e| Error::Install(format!("write {}: {e}", path.display())))?;
  file
    .sync_all()
    .await
    .map_err(|e| Error::Install(format!("fsync {}: {e}", path.display())))?;
  Ok(())
}

#[derive(Debug)]
pub struct StagedPaths {
  pub cert_path: PathBuf,
  pub chain_path: PathBuf,
  pub key_path: PathBuf,
}

enum StagingDir {
  Owned(tempfile::TempDir),
  Borrowed(PathBuf),
}

impl StagingDir {
  fn path(&self) -> &Path {
    match self {
      Self::Owned(d) => d.path(),
      Self::Borrowed(p) => p,
    }
  }
}

#[derive(Debug, Deserialize)]
struct ListResponse {
  success: bool,
  #[serde(default)]
  data: ListData,
}

#[derive(Debug, Default, Deserialize)]
struct ListData {
  #[serde(default)]
  certificates: Vec<ListCertEntry>,
}

#[derive(Debug, Deserialize)]
struct ListCertEntry {
  id: String,
  desc: String,
}

#[derive(Debug, Deserialize)]
struct ImportResponse {
  success: bool,
  #[serde(default)]
  error: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
  use std::os::unix::fs::PermissionsExt;

  use super::*;

  fn issued() -> IssuedCert {
    IssuedCert {
      cert_pem: "LEAF\n".to_owned(),
      chain_pem: "INTER\n".to_owned(),
    }
  }

  #[tokio::test]
  async fn stage_writes_three_files_with_correct_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let install = DsmInstall::new("Kushtaka".to_owned());
    let staged = install.stage(&issued(), "KEY", tmp.path()).await.unwrap();

    assert!(staged.cert_path.exists());
    assert!(staged.chain_path.exists());
    assert!(staged.key_path.exists());

    let key_mode = std::fs::metadata(&staged.key_path)
      .unwrap()
      .permissions()
      .mode()
      & 0o777;
    let cert_mode = std::fs::metadata(&staged.cert_path)
      .unwrap()
      .permissions()
      .mode()
      & 0o777;
    assert_eq!(key_mode, 0o600);
    assert_eq!(cert_mode, 0o644);
  }

  #[test]
  fn list_response_parses_existing_cert() {
    let body = br#"{"success":true,"data":{"certificates":[
      {"id":"abc123","desc":"Other Cert"},
      {"id":"def456","desc":"My Public Site"}
    ]}}"#;
    let parsed: ListResponse = serde_json::from_slice(body).unwrap();
    assert!(parsed.success);
    let found = parsed
      .data
      .certificates
      .into_iter()
      .find(|c| c.desc == "My Public Site")
      .unwrap();
    assert_eq!(found.id, "def456");
  }

  #[test]
  fn list_response_handles_empty_data() {
    let body = br#"{"success":true}"#;
    let parsed: ListResponse = serde_json::from_slice(body).unwrap();
    assert!(parsed.success);
    assert!(parsed.data.certificates.is_empty());
  }

  #[test]
  fn import_response_surfaces_error_block() {
    let body = br#"{"success":false,"error":{"code":403,"message":"forbidden"}}"#;
    let parsed: ImportResponse = serde_json::from_slice(body).unwrap();
    assert!(!parsed.success);
    assert!(parsed.error.is_some());
  }
}
