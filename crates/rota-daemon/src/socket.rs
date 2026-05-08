//! UNIX-socket control surface for the daemon.
//!
//! Binds at `daemon.socket_path`, listens for line-delimited JSON
//! [`rota_core::protocol::Request`] messages, dispatches to handlers
//! that read from the audit store and the bundles, and writes a
//! single [`rota_core::protocol::Response`] line back before
//! closing the connection. The `rota` CLI is the primary client;
//! `nc -U /var/run/rota.sock` works for ad-hoc debugging.
//!
//! Permissions: the socket file is chmodded to 0o600 on bind.
//! Anyone with read access to the socket can request a renewal,
//! which means anyone with that access can talk to your CA over
//! your account, so it gets the same protection as a private key.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rota_core::cert::parse_not_after;
use rota_core::protocol::{
  CertSummary, LogEntry, RenewalOutcome, Request, Response, PROTOCOL_VERSION,
};
use rota_core::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::audit::AuditStore;
use crate::backends::CertBackends;
use crate::renewer::CertRenewer;

const SOCKET_MODE: u32 = 0o600;

/// Daemon-side handle that owns the listener and the references the
/// handlers need.
#[derive(Clone)]
pub struct SocketServer {
  bundles: Arc<Vec<CertBackends>>,
  audit: Arc<dyn AuditStore>,
  renewer: Arc<CertRenewer>,
}

impl SocketServer {
  pub fn new(
    bundles: Arc<Vec<CertBackends>>,
    audit: Arc<dyn AuditStore>,
    renewer: Arc<CertRenewer>,
  ) -> Self {
    Self {
      bundles,
      audit,
      renewer,
    }
  }

  /// Bind the socket and accept connections forever.
  pub async fn serve(self, path: PathBuf) -> Result<()> {
    // Drop any stale socket left behind by a prior crash; UnixListener
    // refuses to bind otherwise. Best-effort: if the file doesn't
    // exist we ignore the error; if it's a real file (not a socket)
    // we still want to fail loudly later when bind() rejects it.
    let _ = std::fs::remove_file(&path);

    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)
        .map_err(|e| rota_core::Error::Install(format!("socket dir {}: {e}", parent.display())))?;
    }

    let listener = UnixListener::bind(&path)
      .map_err(|e| rota_core::Error::Install(format!("bind {}: {e}", path.display())))?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE));

    info!(path = %path.display(), "control socket listening");

    loop {
      match listener.accept().await {
        Ok((stream, _addr)) => {
          let server = self.clone();
          tokio::spawn(async move {
            if let Err(e) = server.handle_connection(stream).await {
              warn!(error = %e, "control socket connection error");
            }
          });
        }
        Err(e) => {
          warn!(error = %e, "accept failed");
        }
      }
    }
  }

  async fn handle_connection(&self, stream: UnixStream) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() || line.is_empty() {
      return Ok(());
    }

    let response = match serde_json::from_str::<Request>(line.trim_end()) {
      Ok(req) => self.dispatch(req).await,
      Err(e) => Response::error(format!("invalid request: {e}")),
    };

    let mut payload =
      serde_json::to_vec(&response).unwrap_or_else(|e| serialise_error_fallback(&e.to_string()));
    payload.push(b'\n');
    let _ = write.write_all(&payload).await;
    let _ = write.flush().await;
    let _ = write.shutdown().await;
    Ok(())
  }

  async fn dispatch(&self, request: Request) -> Response {
    debug!(?request, "control socket request");
    match request {
      Request::Status => self.status().await,
      Request::Renew { cert_id } => self.renew(&cert_id).await,
      Request::Log { cert_id, limit } => self.log(&cert_id, limit).await,
    }
  }

  async fn status(&self) -> Response {
    let mut out = Vec::with_capacity(self.bundles.len());
    for bundle in self.bundles.iter() {
      out.push(self.summarise(bundle).await);
    }
    Response::Status {
      protocol_version: PROTOCOL_VERSION,
      certs: out,
    }
  }

  async fn summarise(&self, bundle: &CertBackends) -> CertSummary {
    let install_name = bundle.install.as_ref().map(|i| i.name().to_owned());

    let (not_after, days_until_expiry) = match &bundle.install {
      Some(install) => match install.current_cert_pem(&bundle.config.id).await {
        Ok(Some(pem)) => match parse_not_after(&pem) {
          Ok(na) => {
            let days = (na - chrono::Utc::now()).num_days();
            (Some(na), Some(days))
          }
          Err(_) => (None, None),
        },
        _ => (None, None),
      },
      None => (None, None),
    };

    let (last_renewal_at, last_renewal_status, last_renewal_error) =
      match self.audit.latest_renewal(&bundle.config.id).await {
        Ok(Some(record)) => (
          Some(record.started_at),
          Some(record.status.as_str().to_owned()),
          record.error,
        ),
        _ => (None, None, None),
      };

    CertSummary {
      id: bundle.config.id.clone(),
      description: bundle.config.description.clone(),
      domains: bundle.config.domains.clone(),
      ca_backend: bundle.ca.name().to_owned(),
      registrar_backend: bundle.registrar.name().to_owned(),
      install_backend: install_name,
      not_after,
      days_until_expiry,
      last_renewal_at,
      last_renewal_status,
      last_renewal_error,
    }
  }

  async fn renew(&self, cert_id: &str) -> Response {
    let Some(bundle) = self.bundles.iter().find(|b| b.config.id == cert_id) else {
      return Response::error(format!("unknown cert: {cert_id}"));
    };
    let outcome = match self.renewer.run(bundle).await {
      Ok(()) => RenewalOutcome::Success,
      Err(_) => RenewalOutcome::Failed,
    };
    let renewal_id = self
      .audit
      .latest_renewal(cert_id)
      .await
      .ok()
      .flatten()
      .map(|r| r.id.0)
      .unwrap_or_default();
    Response::Renew {
      protocol_version: PROTOCOL_VERSION,
      renewal_id,
      outcome,
    }
  }

  async fn log(&self, cert_id: &str, _limit: Option<usize>) -> Response {
    // v0.2 ships with the latest-renewal-only summary. A full
    // pageable log lands once the audit store grows the
    // `list_renewals` accessor; that's a small follow-up.
    let entry = match self.audit.latest_renewal(cert_id).await {
      Ok(Some(record)) => Some(LogEntry {
        renewal_id: record.id.0,
        started_at: record.started_at,
        completed_at: record.completed_at,
        status: record.status.as_str().to_owned(),
        error: record.error,
      }),
      Ok(None) => None,
      Err(e) => return Response::error(format!("audit read failed: {e}")),
    };
    Response::Log {
      protocol_version: PROTOCOL_VERSION,
      cert_id: cert_id.to_owned(),
      events: entry.into_iter().collect(),
    }
  }
}

/// Last-resort serialisation when even `serde_json::to_vec(&Response)`
/// fails (which would imply a non-finite chrono datetime or similar).
/// We hand-shape an Error response so the client still gets a parseable
/// line.
fn serialise_error_fallback(detail: &str) -> Vec<u8> {
  let safe = detail.replace('"', "'");
  format!(
    r#"{{"kind":"error","protocol_version":{PROTOCOL_VERSION},"message":"serialise: {safe}"}}"#
  )
  .into_bytes()
}

/// Convenience wrapper so the daemon can `tokio::spawn` it.
pub async fn run(server: SocketServer, path: impl AsRef<Path>) -> Result<()> {
  server.serve(path.as_ref().to_owned()).await
}

#[cfg(test)]
mod tests;
