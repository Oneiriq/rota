//! HAProxy install backend.
//!
//! Composes [`FilesystemInstall`] for the on-disk copy (so an
//! operator restart picks up the latest cert from disk and
//! `current_cert_pem` works without round-tripping the runtime API)
//! and pushes the new cert to HAProxy's admin socket using the
//! runtime API hot-swap sequence:
//!
//! ```text
//! set ssl cert <storage_name> <<EOL
//! <leaf PEM>
//! <chain PEM>
//! <private key PEM>
//! EOL
//!
//! commit ssl cert <storage_name>
//! ```
//!
//! No reload. No dropped TCP connections. HAProxy hands the new
//! certificate to live SNI lookups on next handshake. Failure of
//! either command is surfaced as an `Install` error so the renewer
//! records it on the audit log; the staged transaction is left for
//! HAProxy to time out (it cleans up automatically), which avoids
//! a follow-up `abort ssl cert` that could itself fail and obscure
//! the original error.
//!
//! Requires HAProxy 2.x or later with the admin socket exposed:
//!
//! ```text
//! global
//!     stats socket /run/haproxy/admin.sock mode 660 level admin
//! ```

use std::path::PathBuf;

use async_trait::async_trait;
use rota_core::backend::{InstallBackend, IssuedCert};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, info};

use super::filesystem::FilesystemInstall;

#[derive(Debug, Clone)]
pub struct HaproxyInstall {
  filesystem: FilesystemInstall,
  socket_path: PathBuf,
  cert_storage_name: String,
}

impl HaproxyInstall {
  pub fn new(
    directory: PathBuf,
    cert_id: String,
    socket_path: PathBuf,
    cert_storage_name: String,
  ) -> Self {
    Self {
      filesystem: FilesystemInstall::new(directory, cert_id),
      socket_path,
      cert_storage_name,
    }
  }

  async fn push_to_haproxy(&self, cert: &IssuedCert, private_key_pem: &str) -> Result<()> {
    let bundle = pem_bundle(cert, private_key_pem);
    let storage = &self.cert_storage_name;

    self
      .send_command(&format!("set ssl cert {storage} <<\n{bundle}\n"))
      .await?;
    debug!(storage = %storage, "haproxy: set ssl cert staged");

    self
      .send_command(&format!("commit ssl cert {storage}\n"))
      .await?;
    info!(storage = %storage, "haproxy: cert committed via runtime api");
    Ok(())
  }

  /// Send a single admin-socket command, read the full response, and
  /// turn HAProxy's English-prose error replies into an `Install`
  /// error. Each command opens a fresh connection so connection
  /// state from one command can't leak into the next; the admin
  /// socket is single-shot by default anyway (no `prompt` mode).
  async fn send_command(&self, command: &str) -> Result<String> {
    let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
      Error::Install(format!(
        "haproxy connect {}: {}",
        self.socket_path.display(),
        redact(&e.to_string())
      ))
    })?;

    stream.write_all(command.as_bytes()).await.map_err(|e| {
      Error::Install(format!(
        "haproxy write to {}: {}",
        self.socket_path.display(),
        redact(&e.to_string())
      ))
    })?;
    stream.shutdown().await.map_err(|e| {
      Error::Install(format!(
        "haproxy shutdown write: {}",
        redact(&e.to_string())
      ))
    })?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).await.map_err(|e| {
      Error::Install(format!(
        "haproxy read from {}: {}",
        self.socket_path.display(),
        redact(&e.to_string())
      ))
    })?;

    if looks_like_error(&buf) {
      return Err(Error::Install(format!(
        "haproxy runtime api: {}",
        redact(buf.trim())
      )));
    }
    Ok(buf)
  }
}

#[async_trait]
impl InstallBackend for HaproxyInstall {
  fn name(&self) -> &str {
    "haproxy"
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
    self.push_to_haproxy(cert, private_key_pem).await?;
    Ok(())
  }

  async fn current_cert_pem(&self, cert_id: &str) -> Result<Option<String>> {
    self.filesystem.current_cert_pem(cert_id).await
  }
}

/// Concatenate cert + chain + private key into the single PEM block
/// HAProxy expects on the runtime API. Each section ends with exactly
/// one newline so the block parses cleanly regardless of whether the
/// input PEMs had trailing newlines.
fn pem_bundle(cert: &IssuedCert, private_key_pem: &str) -> String {
  let mut out =
    String::with_capacity(cert.cert_pem.len() + cert.chain_pem.len() + private_key_pem.len() + 8);
  push_normalised(&mut out, &cert.cert_pem);
  push_normalised(&mut out, &cert.chain_pem);
  push_normalised(&mut out, private_key_pem);
  out
}

fn push_normalised(out: &mut String, pem: &str) {
  out.push_str(pem.trim_end_matches('\n'));
  out.push('\n');
}

/// HAProxy's admin socket emits English-prose responses. Success
/// replies contain "Success", "updated", "committing", "Created";
/// errors include "unable", "not found", "no such", "error", and
/// the universal "[ALERT]". Match conservatively: a missing-keyword
/// success path returns the body and the caller can inspect.
fn looks_like_error(response: &str) -> bool {
  let lower = response.to_ascii_lowercase();
  // Anything containing these tokens is a hard error.
  for needle in [
    "unable to",
    "no such",
    "not found",
    "[alert]",
    "haproxy was compiled without",
    "ssl certificate not found",
    "transaction failed",
  ] {
    if lower.contains(needle) {
      return true;
    }
  }
  false
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;
  use tokio::net::UnixListener;
  use tokio::sync::Mutex;

  fn issued_cert() -> IssuedCert {
    IssuedCert {
      cert_pem: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_owned(),
      chain_pem: "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n".to_owned(),
    }
  }

  /// Spin up a UNIX socket that captures every command it receives
  /// and replies with `success_reply` for every connection (or
  /// `error_reply` if the command count exceeds `success_count`).
  async fn mock_socket(
    success_reply: &'static str,
    success_count: usize,
    error_reply: &'static str,
  ) -> (PathBuf, Arc<Mutex<Vec<String>>>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("haproxy.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_task = Arc::clone(&captured);

    tokio::spawn(async move {
      let mut counter = 0usize;
      loop {
        let Ok((mut stream, _)) = listener.accept().await else {
          return;
        };
        let captured = Arc::clone(&captured_for_task);
        counter += 1;
        let reply = if counter <= success_count {
          success_reply
        } else {
          error_reply
        };
        tokio::spawn(async move {
          let mut buf = String::new();
          let _ = stream.read_to_string(&mut buf).await;
          captured.lock().await.push(buf);
          let _ = stream.write_all(reply.as_bytes()).await;
          let _ = stream.shutdown().await;
        });
      }
    });

    // Yield once so the listener task is registered before the test
    // tries to connect.
    tokio::task::yield_now().await;
    (socket_path, captured, tmp)
  }

  #[test]
  fn pem_bundle_concatenates_cert_chain_key_with_one_trailing_newline_each() {
    let cert = issued_cert();
    let bundle = pem_bundle(
      &cert,
      "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
    );
    let leaf_idx = bundle.find("LEAF").unwrap();
    let inter_idx = bundle.find("INTER").unwrap();
    let key_idx = bundle.find("KEY").unwrap();
    assert!(leaf_idx < inter_idx, "leaf must precede chain");
    assert!(inter_idx < key_idx, "chain must precede private key");
    assert!(bundle.ends_with('\n'));
    assert!(!bundle.contains("\n\n\n"), "no triple-blank lines");
  }

  #[test]
  fn looks_like_error_matches_haproxy_error_phrases() {
    assert!(looks_like_error("Unable to allocate"));
    assert!(looks_like_error("No such file or directory"));
    assert!(looks_like_error("[ALERT] something"));
    assert!(looks_like_error("SSL certificate not found"));
    assert!(!looks_like_error("Success"));
    assert!(!looks_like_error(
      "Transaction created for certificate /etc/.../example.pem"
    ));
    assert!(!looks_like_error(
      "Committing /etc/haproxy/certs/example.pem\nSuccess!"
    ));
  }

  #[tokio::test]
  async fn install_writes_files_and_sends_set_then_commit() {
    let (socket_path, captured, _tmp) = mock_socket(
      "Transaction created for certificate /etc/haproxy/certs/example.pem\nCommitting...\nSuccess!\n",
      4, // every connection succeeds
      "[ALERT] should not happen",
    )
    .await;

    let dir_tmp = tempfile::tempdir().unwrap();
    let install = HaproxyInstall::new(
      dir_tmp.path().to_owned(),
      "haproxy-ok".to_owned(),
      socket_path,
      "/etc/haproxy/certs/example.pem".to_owned(),
    );

    install
      .install(
        &issued_cert(),
        "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
        &[],
      )
      .await
      .unwrap();

    // Files landed on disk.
    assert!(dir_tmp.path().join("haproxy-ok.crt").exists());
    assert!(dir_tmp.path().join("haproxy-ok.key").exists());

    let cmds = captured.lock().await;
    assert_eq!(cmds.len(), 2, "expected set + commit, got {:?}", *cmds);
    assert!(
      cmds[0].starts_with("set ssl cert /etc/haproxy/certs/example.pem <<\n"),
      "first command must be set ssl cert: {}",
      cmds[0]
    );
    assert!(cmds[0].contains("LEAF"));
    assert!(cmds[0].contains("INTER"));
    assert!(cmds[0].contains("KEY"));
    assert_eq!(
      cmds[1].trim(),
      "commit ssl cert /etc/haproxy/certs/example.pem"
    );
  }

  #[tokio::test]
  async fn install_errors_when_haproxy_returns_error_reply() {
    let (socket_path, _captured, _tmp) = mock_socket(
      "[ALERT] unable to load certificate\n",
      4,
      "[ALERT] should not happen",
    )
    .await;

    let dir_tmp = tempfile::tempdir().unwrap();
    let install = HaproxyInstall::new(
      dir_tmp.path().to_owned(),
      "haproxy-fail".to_owned(),
      socket_path,
      "/etc/haproxy/certs/example.pem".to_owned(),
    );

    let err = install
      .install(&issued_cert(), "PRIVKEY", &[])
      .await
      .expect_err("[ALERT] reply must surface");
    assert!(
      err.to_string().contains("haproxy runtime api"),
      "got: {err}"
    );
  }

  #[tokio::test]
  async fn install_errors_when_socket_unreachable() {
    let dir_tmp = tempfile::tempdir().unwrap();
    let install = HaproxyInstall::new(
      dir_tmp.path().to_owned(),
      "haproxy-unreachable".to_owned(),
      PathBuf::from("/nonexistent/haproxy.sock"),
      "/etc/haproxy/certs/example.pem".to_owned(),
    );

    let err = install
      .install(&issued_cert(), "PRIVKEY", &[])
      .await
      .expect_err("missing socket must fail");
    assert!(err.to_string().contains("haproxy connect"), "got: {err}");

    // Filesystem write happened before the runtime-api push attempt;
    // the on-disk cert is still useful so an operator can manually
    // run `set ssl cert` once they fix the socket path.
    assert!(dir_tmp.path().join("haproxy-unreachable.crt").exists());
  }

  #[tokio::test]
  async fn current_cert_pem_delegates_to_filesystem() {
    let (socket_path, _captured, _tmp) = mock_socket("Success!\n", 4, "[ALERT]").await;
    let dir_tmp = tempfile::tempdir().unwrap();
    let install = HaproxyInstall::new(
      dir_tmp.path().to_owned(),
      "haproxy-delegate".to_owned(),
      socket_path,
      "/etc/haproxy/certs/example.pem".to_owned(),
    );
    assert!(install
      .current_cert_pem("haproxy-delegate")
      .await
      .unwrap()
      .is_none());
    install
      .install(&issued_cert(), "PRIVKEY", &[])
      .await
      .unwrap();
    let pem = install.current_cert_pem("haproxy-delegate").await.unwrap();
    assert!(pem.unwrap().contains("LEAF"));
  }
}
