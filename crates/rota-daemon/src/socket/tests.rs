use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use rota_core::backend::{CABackend, DcvChallenge, InstallBackend, IssuedCert, RegistrarBackend};
use rota_core::config::{CaSpec, CertConfig, InstallSpec, RegistrarSpec};
use rota_core::protocol::{Request, Response};
use rota_core::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::*;
use crate::audit::SqliteAuditStore;
use crate::backends::CertBackends;

#[derive(Default)]
struct StubCa;
#[async_trait]
impl CABackend for StubCa {
  fn name(&self) -> &str {
    "stub-ca"
  }
  async fn submit(&self, _: &[String], _: &str) -> Result<DcvChallenge> {
    unreachable!("status path does not call CA")
  }
  async fn await_issuance(&self, _: &[String]) -> Result<IssuedCert> {
    unreachable!("status path does not call CA")
  }
}

#[derive(Default)]
struct StubRegistrar;
#[async_trait]
impl RegistrarBackend for StubRegistrar {
  fn name(&self) -> &str {
    "stub-reg"
  }
  async fn publish_txt(&self, _: &DcvChallenge) -> Result<()> {
    unreachable!("status path does not call registrar")
  }
  async fn remove_txt(&self, _: &DcvChallenge) -> Result<()> {
    unreachable!("status path does not call registrar")
  }
}

#[derive(Default)]
struct StubInstall;
#[async_trait]
impl InstallBackend for StubInstall {
  fn name(&self) -> &str {
    "stub-install"
  }
  async fn install(&self, _: &IssuedCert, _: &str, _: &[String]) -> Result<()> {
    Ok(())
  }
  async fn current_cert_pem(&self, _: &str) -> Result<Option<String>> {
    Ok(None)
  }
}

fn cert_config(id: &str) -> CertConfig {
  CertConfig {
    id: id.to_owned(),
    description: "test cert".to_owned(),
    domains: vec!["example.com".to_owned()],
    key_path: PathBuf::from("/tmp/unused"),
    ca: CaSpec::Namecheap { ssl_id: 1 },
    registrar: RegistrarSpec::Namecheap,
    install: InstallSpec::Filesystem {
      directory: PathBuf::from("/tmp/unused"),
    },
  }
}

async fn run_request(server: SocketServer, request: Request) -> Response {
  // Bind to a tempdir socket, fire one connection, close.
  let tmp = tempfile::tempdir().unwrap();
  let path = tmp.path().join("rota.sock");
  let path_clone = path.clone();
  let server_task = tokio::spawn(async move { server.serve(path_clone).await });

  // Wait for the listener to actually be ready (bind is sync inside
  // serve but the path appears asynchronously to outside observers).
  for _ in 0..50 {
    if path.exists() {
      break;
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
  }

  let stream = UnixStream::connect(&path).await.unwrap();
  let (read, mut write) = stream.into_split();
  let mut payload = serde_json::to_vec(&request).unwrap();
  payload.push(b'\n');
  write.write_all(&payload).await.unwrap();
  write.flush().await.unwrap();
  // Don't shutdown the writer; some readers race the EOF detection.
  // Just read one line.
  let mut reader = BufReader::new(read);
  let mut line = String::new();
  reader.read_line(&mut line).await.unwrap();

  // Tear down the listener task (the server loops forever).
  server_task.abort();

  serde_json::from_str(line.trim_end()).unwrap()
}

#[tokio::test]
async fn status_returns_summary_for_each_configured_cert() {
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap()) as Arc<dyn AuditStore>;
  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let bundles = Arc::new(vec![
    CertBackends {
      config: cert_config("alpha"),
      ca: Arc::new(StubCa) as Arc<dyn CABackend>,
      registrar: Arc::new(StubRegistrar) as Arc<dyn RegistrarBackend>,
      install: Some(Arc::new(StubInstall) as Arc<dyn InstallBackend>),
    },
    CertBackends {
      config: cert_config("beta"),
      ca: Arc::new(StubCa) as Arc<dyn CABackend>,
      registrar: Arc::new(StubRegistrar) as Arc<dyn RegistrarBackend>,
      install: None,
    },
  ]);
  let server = SocketServer::new(bundles, audit, renewer);

  match run_request(server, Request::Status).await {
    Response::Status { certs, .. } => {
      assert_eq!(certs.len(), 2);
      assert_eq!(certs[0].id, "alpha");
      assert_eq!(certs[0].install_backend.as_deref(), Some("stub-install"));
      assert!(certs[0].not_after.is_none()); // StubInstall returns None
      assert!(certs[0].last_renewal_at.is_none()); // No renewals yet
      assert_eq!(certs[1].id, "beta");
      assert!(certs[1].install_backend.is_none());
    }
    other => panic!("expected Status response, got {other:?}"),
  }
}

#[tokio::test]
async fn invalid_json_returns_error_response() {
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap()) as Arc<dyn AuditStore>;
  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let bundles = Arc::new(vec![]);
  let server = SocketServer::new(bundles, audit, renewer);

  // Connect manually so we can send malformed bytes.
  let tmp = tempfile::tempdir().unwrap();
  let path = tmp.path().join("rota.sock");
  let path_clone = path.clone();
  let server_task = tokio::spawn(async move { server.serve(path_clone).await });
  for _ in 0..50 {
    if path.exists() {
      break;
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
  }
  let stream = UnixStream::connect(&path).await.unwrap();
  let (read, mut write) = stream.into_split();
  write.write_all(b"this is not json\n").await.unwrap();
  write.flush().await.unwrap();
  let mut reader = BufReader::new(read);
  let mut line = String::new();
  reader.read_line(&mut line).await.unwrap();
  server_task.abort();

  let resp: Response = serde_json::from_str(line.trim_end()).unwrap();
  match resp {
    Response::Error { message, .. } => {
      assert!(message.contains("invalid request"));
    }
    other => panic!("expected Error response, got {other:?}"),
  }
}

#[tokio::test]
async fn unknown_cert_id_in_renew_yields_error_response() {
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap()) as Arc<dyn AuditStore>;
  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let bundles = Arc::new(vec![]);
  let server = SocketServer::new(bundles, audit, renewer);

  match run_request(
    server,
    Request::Renew {
      cert_id: "ghost".to_owned(),
    },
  )
  .await
  {
    Response::Error { message, .. } => {
      assert!(message.contains("ghost"));
    }
    other => panic!("expected Error response, got {other:?}"),
  }
}

#[tokio::test]
async fn log_for_unknown_cert_returns_empty_event_list() {
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap()) as Arc<dyn AuditStore>;
  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let bundles = Arc::new(vec![]);
  let server = SocketServer::new(bundles, audit, renewer);

  match run_request(
    server,
    Request::Log {
      cert_id: "unknown".to_owned(),
      limit: None,
    },
  )
  .await
  {
    Response::Log {
      cert_id, events, ..
    } => {
      assert_eq!(cert_id, "unknown");
      assert!(events.is_empty());
    }
    other => panic!("expected Log response, got {other:?}"),
  }
}
