//! Plain-filesystem install backend.
//!
//! Lays the issued cert + chain + private key down in a configured
//! directory under predictable filenames so any service that reads
//! disk-based PEM (nginx, HAProxy, Caddy, custom Rust + rustls) can
//! pick them up. Filenames mirror the certbot convention so existing
//! reload scripts that grep for `fullchain.pem` / `privkey.pem` work
//! unchanged.
//!
//! Writes are atomic per-file: each artifact is written to a sibling
//! `.tmp` file, fsynced, then renamed into place. If the daemon
//! crashes mid-renewal the consuming service still sees the previous
//! cert intact rather than a half-written one.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use rota_core::backend::{InstallBackend, IssuedCert};
use rota_core::{Error, Result};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::info;

/// Mode for cert files (world-readable; the cert is public information).
const CERT_MODE: u32 = 0o644;
/// Mode for the private key (owner read/write only).
const KEY_MODE: u32 = 0o600;

/// Per-cert tmp-file disambiguator. Multiple in-flight renewals on the
/// same directory must not collide on the staging filename.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct FilesystemInstall {
  directory: PathBuf,
  cert_id: String,
}

impl FilesystemInstall {
  pub fn new(directory: PathBuf, cert_id: String) -> Self {
    Self { directory, cert_id }
  }

  fn path(&self, suffix: &str) -> PathBuf {
    self.directory.join(format!("{}.{}", self.cert_id, suffix))
  }
}

#[async_trait]
impl InstallBackend for FilesystemInstall {
  fn name(&self) -> &str {
    "filesystem"
  }

  async fn install(
    &self,
    cert: &IssuedCert,
    private_key_pem: &str,
    _domains: &[String],
  ) -> Result<()> {
    fs::create_dir_all(&self.directory).await.map_err(|e| {
      Error::Install(format!(
        "create directory {}: {e}",
        self.directory.display()
      ))
    })?;

    let cert_path = self.path("crt");
    let chain_path = self.path("chain.crt");
    let fullchain_path = self.path("fullchain.crt");
    let key_path = self.path("key");

    write_atomic(&cert_path, cert.cert_pem.as_bytes(), CERT_MODE).await?;
    write_atomic(&chain_path, cert.chain_pem.as_bytes(), CERT_MODE).await?;
    write_atomic(
      &fullchain_path,
      &concat_pem(&cert.cert_pem, &cert.chain_pem),
      CERT_MODE,
    )
    .await?;
    write_atomic(&key_path, private_key_pem.as_bytes(), KEY_MODE).await?;

    info!(
      cert_id = %self.cert_id,
      directory = %self.directory.display(),
      "filesystem install complete"
    );
    Ok(())
  }
}

/// Concatenate the leaf cert and chain into a single PEM bundle.
/// Ensures exactly one newline between the two — both inputs may or
/// may not have a trailing newline.
fn concat_pem(cert_pem: &str, chain_pem: &str) -> Vec<u8> {
  let cert_trim = cert_pem.trim_end_matches('\n');
  let chain_trim = chain_pem.trim_start_matches('\n');
  let mut buf = Vec::with_capacity(cert_pem.len() + chain_pem.len() + 1);
  buf.extend_from_slice(cert_trim.as_bytes());
  buf.push(b'\n');
  buf.extend_from_slice(chain_trim.as_bytes());
  if !chain_trim.ends_with('\n') {
    buf.push(b'\n');
  }
  buf
}

/// Write `contents` to `path` atomically with the requested mode.
///
/// Strategy: write to `path.tmp.<counter>`, fsync the file, fsync the
/// parent directory, rename into place. The rename is atomic on every
/// POSIX filesystem rota cares about. If anything fails before the
/// rename, the destination keeps its previous content untouched.
async fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
  let tmp = staging_path(path);
  let parent = path
    .parent()
    .ok_or_else(|| Error::Install(format!("path has no parent: {}", path.display())))?;

  let mut file = fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .mode(mode)
    .open(&tmp)
    .await
    .map_err(|e| Error::Install(format!("open {}: {e}", tmp.display())))?;

  file
    .write_all(contents)
    .await
    .map_err(|e| Error::Install(format!("write {}: {e}", tmp.display())))?;
  file
    .sync_all()
    .await
    .map_err(|e| Error::Install(format!("fsync {}: {e}", tmp.display())))?;
  drop(file);

  fs::rename(&tmp, path).await.map_err(|e| {
    Error::Install(format!(
      "rename {} -> {}: {e}",
      tmp.display(),
      path.display()
    ))
  })?;

  // Fsync the parent so the rename itself is durable. Best-effort;
  // some filesystems (e.g. tmpfs in tests) reject this and that's OK.
  if let Ok(dir) = fs::File::open(parent).await {
    let _ = dir.sync_all().await;
  }

  Ok(())
}

fn staging_path(path: &Path) -> PathBuf {
  let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
  let mut name = path.file_name().map(|n| n.to_owned()).unwrap_or_default();
  name.push(format!(".tmp.{n}"));
  path.with_file_name(name)
}

#[cfg(test)]
mod tests {
  use std::os::unix::fs::PermissionsExt;

  use super::*;

  fn issued_cert() -> IssuedCert {
    IssuedCert {
      cert_pem: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_owned(),
      chain_pem: "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n".to_owned(),
    }
  }

  #[tokio::test]
  async fn writes_four_files_with_correct_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let install = FilesystemInstall::new(tmp.path().to_owned(), "kushtaka-public".to_owned());
    install
      .install(&issued_cert(), "PRIVKEYPEM", &[])
      .await
      .unwrap();

    let crt = tmp.path().join("kushtaka-public.crt");
    let chain = tmp.path().join("kushtaka-public.chain.crt");
    let fullchain = tmp.path().join("kushtaka-public.fullchain.crt");
    let key = tmp.path().join("kushtaka-public.key");

    assert!(crt.exists());
    assert!(chain.exists());
    assert!(fullchain.exists());
    assert!(key.exists());

    let key_mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    let crt_mode = std::fs::metadata(&crt).unwrap().permissions().mode() & 0o777;
    assert_eq!(key_mode, 0o600, "private key must be owner-only");
    assert_eq!(crt_mode, 0o644, "cert must be world-readable");
  }

  #[tokio::test]
  async fn fullchain_concatenates_leaf_and_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let install = FilesystemInstall::new(tmp.path().to_owned(), "test".to_owned());
    install.install(&issued_cert(), "KEY", &[]).await.unwrap();

    let fullchain = std::fs::read_to_string(tmp.path().join("test.fullchain.crt")).unwrap();
    assert!(fullchain.contains("LEAF"));
    assert!(fullchain.contains("INTER"));
    let leaf_idx = fullchain.find("LEAF").unwrap();
    let inter_idx = fullchain.find("INTER").unwrap();
    assert!(leaf_idx < inter_idx, "leaf must come before chain");
    assert!(fullchain.ends_with('\n'));
  }

  #[tokio::test]
  async fn creates_missing_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("nested/deeper");
    let install = FilesystemInstall::new(nested.clone(), "test".to_owned());
    install.install(&issued_cert(), "KEY", &[]).await.unwrap();
    assert!(nested.join("test.crt").exists());
  }

  #[tokio::test]
  async fn overwrites_existing_files() {
    let tmp = tempfile::tempdir().unwrap();
    let install = FilesystemInstall::new(tmp.path().to_owned(), "test".to_owned());
    let mut first = issued_cert();
    install.install(&first, "KEY1", &[]).await.unwrap();

    first.cert_pem = "-----BEGIN CERTIFICATE-----\nLEAF2\n-----END CERTIFICATE-----\n".into();
    install.install(&first, "KEY2", &[]).await.unwrap();

    let crt = std::fs::read_to_string(tmp.path().join("test.crt")).unwrap();
    let key = std::fs::read_to_string(tmp.path().join("test.key")).unwrap();
    assert!(crt.contains("LEAF2"));
    assert!(!crt.contains("LEAF\n"));
    assert_eq!(key, "KEY2");
  }

  #[test]
  fn concat_pem_handles_missing_trailing_newlines() {
    let combined = concat_pem("CERT", "CHAIN");
    assert_eq!(std::str::from_utf8(&combined).unwrap(), "CERT\nCHAIN\n");

    let combined = concat_pem("CERT\n", "CHAIN\n");
    assert_eq!(std::str::from_utf8(&combined).unwrap(), "CERT\nCHAIN\n");

    let combined = concat_pem("CERT\n\n", "\nCHAIN");
    assert_eq!(std::str::from_utf8(&combined).unwrap(), "CERT\nCHAIN\n");
  }
}
