use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rota_core::backend::{CABackend, DcvBackend, DcvChallenge, InstallBackend, IssuedCert};
use rota_core::config::{CaSpec, CertConfig, DcvSpec, InstallSpec};
use rota_core::Result;

use super::*;
use crate::audit::{AuditStore, SqliteAuditStore};
use crate::backends::CertBackends;

async fn open_audit() -> Arc<dyn AuditStore> {
  Arc::new(SqliteAuditStore::open_in_memory().await.unwrap())
}

#[derive(Default)]
struct MockCa {
  submit_calls: AtomicUsize,
  await_calls: AtomicUsize,
  fail_await: bool,
}

#[async_trait]
impl CABackend for MockCa {
  fn name(&self) -> &str {
    "mock-ca"
  }
  async fn submit(&self, _domains: &[String], _csr_pem: &str) -> Result<Vec<DcvChallenge>> {
    self.submit_calls.fetch_add(1, Ordering::SeqCst);
    Ok(vec![DcvChallenge::Dns01 {
      record_name: "_acme-challenge.example.com".to_owned(),
      record_value: "deadbeef".to_owned(),
      ttl: 60,
    }])
  }
  async fn await_issuance(&self, _domains: &[String]) -> Result<IssuedCert> {
    self.await_calls.fetch_add(1, Ordering::SeqCst);
    if self.fail_await {
      return Err(rota_core::Error::Ca("ca timeout".to_owned()));
    }
    Ok(IssuedCert {
      cert_pem: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_owned(),
      chain_pem: "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n".to_owned(),
    })
  }
}

#[derive(Default)]
struct MockDcv {
  publish_calls: AtomicUsize,
  remove_calls: AtomicUsize,
}

#[async_trait]
impl DcvBackend for MockDcv {
  fn name(&self) -> &str {
    "mock-dcv"
  }
  fn supports(&self, _: &DcvChallenge) -> bool {
    true
  }
  async fn publish(&self, _challenge: &DcvChallenge) -> Result<()> {
    self.publish_calls.fetch_add(1, Ordering::SeqCst);
    Ok(())
  }
  async fn remove(&self, _challenge: &DcvChallenge) -> Result<()> {
    self.remove_calls.fetch_add(1, Ordering::SeqCst);
    Ok(())
  }
}

#[derive(Default)]
struct MockInstall {
  install_calls: AtomicUsize,
}

#[async_trait]
impl InstallBackend for MockInstall {
  fn name(&self) -> &str {
    "mock-install"
  }
  async fn install(&self, _cert: &IssuedCert, _key: &str, _domains: &[String]) -> Result<()> {
    self.install_calls.fetch_add(1, Ordering::SeqCst);
    Ok(())
  }
}

fn cert_config(id: &str, key_path: PathBuf) -> CertConfig {
  CertConfig {
    id: id.to_owned(),
    description: String::new(),
    domains: vec!["example.com".to_owned(), "www.example.com".to_owned()],
    key_path,
    ca: CaSpec::Namecheap { ssl_id: 1 },
    dcv: DcvSpec::Namecheap,
    install: InstallSpec::Filesystem {
      directory: PathBuf::from("/tmp/unused"),
    },
  }
}

fn bundle(
  config: CertConfig,
  ca: Arc<MockCa>,
  dcv: Arc<MockDcv>,
  install: Option<Arc<MockInstall>>,
) -> CertBackends {
  CertBackends {
    config,
    ca,
    dcv,
    install: install.map(|i| i as Arc<dyn InstallBackend>),
  }
}

#[tokio::test]
async fn happy_path_runs_every_step_and_audits_success() {
  let audit = open_audit().await;
  let renewer = CertRenewer::new(Arc::clone(&audit));
  let tmp = tempfile::tempdir().unwrap();

  let ca = Arc::new(MockCa::default());
  let dcv = Arc::new(MockDcv::default());
  let install = Arc::new(MockInstall::default());

  let b = bundle(
    cert_config("happy", tmp.path().join("k.key")),
    Arc::clone(&ca),
    Arc::clone(&dcv),
    Some(Arc::clone(&install)),
  );
  renewer.run(&b).await.unwrap();

  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 1);
  assert_eq!(ca.await_calls.load(Ordering::SeqCst), 1);
  assert_eq!(dcv.publish_calls.load(Ordering::SeqCst), 1);
  assert_eq!(dcv.remove_calls.load(Ordering::SeqCst), 1);
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);

  let latest = audit.latest_renewal("happy").await.unwrap().unwrap();
  assert_eq!(latest.status, RenewalStatus::Success);
  assert!(latest.error.is_none());
  let (ok, fail) = audit.count_by_status("happy").await.unwrap();
  assert_eq!((ok, fail), (1, 0));

  // The persistent key was generated.
  assert!(tmp.path().join("k.key").exists());
}

#[tokio::test]
async fn ca_failure_still_removes_dcv_and_records_failure() {
  let audit = open_audit().await;
  let renewer = CertRenewer::new(Arc::clone(&audit));
  let tmp = tempfile::tempdir().unwrap();

  let ca = Arc::new(MockCa {
    fail_await: true,
    ..Default::default()
  });
  let dcv = Arc::new(MockDcv::default());
  let install = Arc::new(MockInstall::default());

  let b = bundle(
    cert_config("flaky", tmp.path().join("k.key")),
    Arc::clone(&ca),
    Arc::clone(&dcv),
    Some(Arc::clone(&install)),
  );
  let err = renewer.run(&b).await.unwrap_err();
  assert!(err.to_string().contains("ca timeout"));

  // DCV cleanup ran even though await_issuance errored.
  assert_eq!(dcv.publish_calls.load(Ordering::SeqCst), 1);
  assert_eq!(dcv.remove_calls.load(Ordering::SeqCst), 1);
  // Install never ran.
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 0);

  let latest = audit.latest_renewal("flaky").await.unwrap().unwrap();
  assert_eq!(latest.status, RenewalStatus::Failed);
  assert!(latest.error.as_deref().unwrap().contains("ca timeout"));
}

#[tokio::test]
async fn reuses_existing_key_on_disk() {
  let audit = open_audit().await;
  let renewer = CertRenewer::new(Arc::clone(&audit));
  let tmp = tempfile::tempdir().unwrap();
  let key_path = tmp.path().join("persistent.key");

  let ca = Arc::new(MockCa::default());
  let dcv = Arc::new(MockDcv::default());

  let b1 = bundle(
    cert_config("rotating", key_path.clone()),
    Arc::clone(&ca),
    Arc::clone(&dcv),
    None,
  );
  renewer.run(&b1).await.unwrap();
  let key_after_first = std::fs::read_to_string(&key_path).unwrap();

  let b2 = bundle(
    cert_config("rotating", key_path.clone()),
    Arc::clone(&ca),
    Arc::clone(&dcv),
    None,
  );
  renewer.run(&b2).await.unwrap();
  let key_after_second = std::fs::read_to_string(&key_path).unwrap();

  assert_eq!(
    key_after_first, key_after_second,
    "private key must persist across renewals"
  );

  let (ok, _) = audit.count_by_status("rotating").await.unwrap();
  assert_eq!(ok, 2);
}

#[tokio::test]
async fn install_skipped_when_no_install_backend() {
  let audit = open_audit().await;
  let renewer = CertRenewer::new(Arc::clone(&audit));
  let tmp = tempfile::tempdir().unwrap();

  let ca = Arc::new(MockCa::default());
  let dcv = Arc::new(MockDcv::default());

  let b = bundle(
    cert_config("no-install", tmp.path().join("k.key")),
    Arc::clone(&ca),
    Arc::clone(&dcv),
    None,
  );
  renewer.run(&b).await.unwrap();

  let latest = audit.latest_renewal("no-install").await.unwrap().unwrap();
  assert_eq!(latest.status, RenewalStatus::Success);
}
