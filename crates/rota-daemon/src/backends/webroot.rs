//! HTTP-01 webroot DCV backend.
//!
//! For each challenge, drops the key authorization at
//! `<directory>/.well-known/acme-challenge/<token>` (mode 644) and
//! removes it after issuance. The operator's existing webserver
//! (nginx, Caddy, Apache, anything that serves static files) is
//! responsible for actually exposing the directory at
//! `http://<domain>/.well-known/acme-challenge/` on port 80.
//!
//! Why webroot instead of a daemon-internal listener: most
//! self-hosters already run a webserver on 80/443. Asking rota to
//! bind 80 means coordinating port handoff (or running rota as
//! root) for one purpose: serving a five-byte file the existing
//! webserver could serve in its sleep. Webroot is the
//! lowest-friction option for that audience. A native listener
//! mode can layer on later if there is real demand.
//!
//! Atomic writes: each token file is written to a sibling `.tmp`
//! and renamed into place so a partial write never serves a
//! truncated key authorization. The remove path tolerates an
//! already-absent file so cleanup is idempotent (matches the trait
//! contract; matters when rota and an operator both delete).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use rota_core::backend::{ChallengeKind, DcvBackend, DcvChallenge};
use rota_core::{Error, Result};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

const CHALLENGE_PATH: &str = ".well-known/acme-challenge";
const TOKEN_FILE_MODE: u32 = 0o644;
const SUPPORTED: &[ChallengeKind] = &[ChallengeKind::Http01];

/// Sibling-file disambiguator for atomic writes. Multiple in-flight
/// renewals on the same directory must not collide on `.tmp`.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct WebrootDcv {
  directory: PathBuf,
}

impl WebrootDcv {
  pub fn new(directory: PathBuf) -> Self {
    Self { directory }
  }

  fn challenge_dir(&self) -> PathBuf {
    self.directory.join(CHALLENGE_PATH)
  }

  fn token_path(&self, token: &str) -> Result<PathBuf> {
    // ACME tokens are RFC 8555 base64url; defence-in-depth against a
    // server that returns a path-traversal-shaped token. The base64url
    // alphabet has no slashes, but the trait contract makes the token
    // an opaque string, and a misbehaving CA shouldn't get a foothold.
    if token.is_empty() || token.contains('/') || token.contains('\\') || token.contains("..") {
      return Err(Error::Registrar(format!(
        "webroot http-01: refusing path-shaped challenge token: {token:?}"
      )));
    }
    Ok(self.challenge_dir().join(token))
  }
}

#[async_trait]
impl DcvBackend for WebrootDcv {
  fn name(&self) -> &str {
    "webroot"
  }

  fn supported_kinds(&self) -> &[ChallengeKind] {
    SUPPORTED
  }

  async fn publish(&self, challenge: &DcvChallenge) -> Result<()> {
    let DcvChallenge::Http01 {
      domain,
      token,
      key_authorization,
    } = challenge
    else {
      return Err(Error::Registrar(format!(
        "webroot dcv only supports http-01, got {}",
        challenge.kind_str()
      )));
    };

    let dir = self.challenge_dir();
    fs::create_dir_all(&dir)
      .await
      .map_err(|e| Error::Registrar(format!("webroot http-01: create {}: {e}", dir.display())))?;

    let path = self.token_path(token)?;
    write_atomic(&path, key_authorization.as_bytes(), TOKEN_FILE_MODE).await?;

    info!(
      domain = %domain,
      token = %token,
      "webroot http-01 token published"
    );
    Ok(())
  }

  async fn remove(&self, challenge: &DcvChallenge) -> Result<()> {
    let DcvChallenge::Http01 { domain, token, .. } = challenge else {
      return Err(Error::Registrar(format!(
        "webroot dcv only supports http-01, got {}",
        challenge.kind_str()
      )));
    };

    let path = self.token_path(token)?;
    match fs::remove_file(&path).await {
      Ok(()) => {
        debug!(domain = %domain, token = %token, "webroot http-01 token removed");
        Ok(())
      }
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
        // Idempotent: a prior cleanup or operator already removed it.
        Ok(())
      }
      Err(e) => Err(Error::Registrar(format!(
        "webroot http-01: remove {}: {e}",
        path.display()
      ))),
    }
  }
}

async fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
  let parent = path
    .parent()
    .ok_or_else(|| Error::Registrar(format!("webroot path has no parent: {}", path.display())))?;
  let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
  let mut tmp_name = path.file_name().map(|s| s.to_owned()).unwrap_or_default();
  tmp_name.push(format!(".tmp.{n}"));
  let tmp = path.with_file_name(tmp_name);

  let mut file = fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .mode(mode)
    .open(&tmp)
    .await
    .map_err(|e| Error::Registrar(format!("webroot open {}: {e}", tmp.display())))?;
  file
    .write_all(contents)
    .await
    .map_err(|e| Error::Registrar(format!("webroot write {}: {e}", tmp.display())))?;
  file
    .sync_all()
    .await
    .map_err(|e| Error::Registrar(format!("webroot fsync {}: {e}", tmp.display())))?;
  drop(file);

  fs::rename(&tmp, path).await.map_err(|e| {
    Error::Registrar(format!(
      "webroot rename {} -> {}: {e}",
      tmp.display(),
      path.display()
    ))
  })?;

  // Best-effort parent fsync so the rename is durable. Some
  // filesystems reject this and that's OK.
  if let Ok(dir) = fs::File::open(parent).await {
    let _ = dir.sync_all().await;
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use std::os::unix::fs::PermissionsExt;

  use super::*;

  fn http01(token: &str, key_auth: &str) -> DcvChallenge {
    DcvChallenge::Http01 {
      domain: "example.com".to_owned(),
      token: token.to_owned(),
      key_authorization: key_auth.to_owned(),
    }
  }

  fn dns01() -> DcvChallenge {
    DcvChallenge::Dns01 {
      record_name: "_acme-challenge.example.com".to_owned(),
      record_value: "x".to_owned(),
      ttl: 60,
    }
  }

  #[tokio::test]
  async fn publish_writes_key_auth_under_well_known() {
    let tmp = tempfile::tempdir().unwrap();
    let solver = WebrootDcv::new(tmp.path().to_owned());
    solver
      .publish(&http01("tok123", "tok123.thumbprint"))
      .await
      .unwrap();

    let path = tmp.path().join(".well-known/acme-challenge").join("tok123");
    assert!(path.exists(), "token file must exist at {}", path.display());
    let body = std::fs::read_to_string(&path).unwrap();
    assert_eq!(body, "tok123.thumbprint");

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "token must be world-readable for webserver");
  }

  #[tokio::test]
  async fn publish_creates_well_known_path_if_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("htdocs");
    let solver = WebrootDcv::new(nested.clone());
    solver.publish(&http01("tok-mkdir", "ka")).await.unwrap();
    assert!(nested.join(".well-known/acme-challenge/tok-mkdir").exists());
  }

  #[tokio::test]
  async fn remove_deletes_token_file() {
    let tmp = tempfile::tempdir().unwrap();
    let solver = WebrootDcv::new(tmp.path().to_owned());
    let c = http01("tok-rm", "ka");
    solver.publish(&c).await.unwrap();
    let path = tmp.path().join(".well-known/acme-challenge/tok-rm");
    assert!(path.exists());

    solver.remove(&c).await.unwrap();
    assert!(!path.exists());
  }

  #[tokio::test]
  async fn remove_is_idempotent_when_token_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let solver = WebrootDcv::new(tmp.path().to_owned());
    // Never published; remove must still succeed.
    solver
      .remove(&http01("never-published", "ka"))
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn rejects_path_traversal_shaped_token() {
    let tmp = tempfile::tempdir().unwrap();
    let solver = WebrootDcv::new(tmp.path().to_owned());
    for evil in ["../etc/passwd", "..", "a/b", "a\\b", ""] {
      let err = solver
        .publish(&http01(evil, "ka"))
        .await
        .expect_err("path-shaped token must fail");
      let _ = err;
    }
  }

  #[tokio::test]
  async fn rejects_dns01_challenge_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let solver = WebrootDcv::new(tmp.path().to_owned());
    let err = solver
      .publish(&dns01())
      .await
      .expect_err("dns-01 must be rejected");
    assert!(err.to_string().contains("http-01"), "got: {err}");
  }

  #[test]
  fn supports_returns_true_only_for_http01() {
    let solver = WebrootDcv::new(PathBuf::from("/tmp/unused"));
    assert!(solver.supports(&http01("t", "k")));
    assert!(!solver.supports(&dns01()));
    assert_eq!(solver.supported_kinds(), &[ChallengeKind::Http01]);
  }
}
