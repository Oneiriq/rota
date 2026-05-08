use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rota_core::backend::{CABackend, DcvBackend, DcvChallenge, InstallBackend, IssuedCert};
use rota_core::cluster::ClusterCoordinator;
use rota_core::config::{CaSpec, CertConfig, DcvSpec, InstallSpec};
use rota_core::Result;

use super::*;
use crate::audit::SqliteAuditStore;
use crate::backends::CertBackends;

struct StubCa;
#[async_trait]
impl CABackend for StubCa {
  fn name(&self) -> &str {
    "stub-ca"
  }
  async fn submit(
    &self,
    _: &[String],
    _: &str,
    _: &[rota_core::backend::ChallengeKind],
  ) -> Result<Vec<DcvChallenge>> {
    unreachable!("install_sync does not call CA")
  }
  async fn await_issuance(&self, _: &[String]) -> Result<IssuedCert> {
    unreachable!("install_sync does not call CA")
  }
}

struct StubDcv;
#[async_trait]
impl DcvBackend for StubDcv {
  fn name(&self) -> &str {
    "stub-dcv"
  }
  fn supported_kinds(&self) -> &[rota_core::backend::ChallengeKind] {
    &[rota_core::backend::ChallengeKind::Dns01]
  }
  async fn publish(&self, _: &DcvChallenge) -> Result<()> {
    unreachable!("install_sync does not call DCV")
  }
  async fn remove(&self, _: &DcvChallenge) -> Result<()> {
    unreachable!("install_sync does not call DCV")
  }
}

/// Recording install backend: tracks the last cert it was asked to
/// install plus a configurable `current_cert_pem` return so the
/// freshness check can be exercised.
struct RecordingInstall {
  install_calls: AtomicUsize,
  last_installed_pem: tokio::sync::Mutex<Option<String>>,
  current_pem: tokio::sync::Mutex<Option<String>>,
}

impl RecordingInstall {
  fn new(initial_local_cert: Option<String>) -> Self {
    Self {
      install_calls: AtomicUsize::new(0),
      last_installed_pem: tokio::sync::Mutex::new(None),
      current_pem: tokio::sync::Mutex::new(initial_local_cert),
    }
  }
}

#[async_trait]
impl InstallBackend for RecordingInstall {
  fn name(&self) -> &str {
    "recording"
  }
  async fn install(&self, cert: &IssuedCert, _key: &str, _domains: &[String]) -> Result<()> {
    self.install_calls.fetch_add(1, Ordering::SeqCst);
    *self.last_installed_pem.lock().await = Some(cert.cert_pem.clone());
    // Reflect the just-installed cert as `current_cert_pem` so a
    // follow-up sweep sees it as fresh.
    *self.current_pem.lock().await = Some(cert.cert_pem.clone());
    Ok(())
  }
  async fn current_cert_pem(&self, _cert_id: &str) -> Result<Option<String>> {
    Ok(self.current_pem.lock().await.clone())
  }
}

/// Fixed-leadership coordinator. Tests instantiate it with the value
/// they want to assert against.
struct FixedLeader {
  is_leader: AtomicBool,
}

impl FixedLeader {
  fn new(leader: bool) -> Self {
    Self {
      is_leader: AtomicBool::new(leader),
    }
  }
}

#[async_trait]
impl ClusterCoordinator for FixedLeader {
  fn name(&self) -> &str {
    "fixed-leader"
  }
  fn node_id(&self) -> &str {
    "test-node"
  }
  fn is_leader(&self) -> bool {
    self.is_leader.load(Ordering::Acquire)
  }
  async fn run(&self) -> Result<()> {
    std::future::pending::<()>().await;
    Ok(())
  }
}

fn cert_config(id: &str, key_path: PathBuf) -> CertConfig {
  CertConfig {
    id: id.to_owned(),
    description: String::new(),
    domains: vec!["example.com".to_owned()],
    key_path,
    ca: CaSpec::Namecheap { ssl_id: 1 },
    dcv: DcvSpec::Namecheap,
    install: InstallSpec::Filesystem {
      directory: PathBuf::from("/tmp/unused"),
    },
  }
}

fn issue_pem(days_valid: i64) -> String {
  use rcgen::{CertificateParams, KeyPair};
  let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
  let now = time::OffsetDateTime::now_utc();
  params.not_before = now;
  params.not_after = now + time::Duration::days(days_valid);
  let key = KeyPair::generate().unwrap();
  let cert = params.self_signed(&key).unwrap();
  cert.pem()
}

async fn build_task(
  cert_id: &str,
  install: Arc<RecordingInstall>,
  is_leader: bool,
) -> (
  InstallSyncTask,
  Arc<dyn AuditStore>,
  Arc<FixedLeader>,
  Arc<RecordingInstall>,
  tempfile::TempDir,
) {
  let tmp = tempfile::tempdir().unwrap();
  let key_path = tmp.path().join("rota.key");
  // Drop a placeholder key so install_sync can read it. ACME / Namecheap
  // would parse it, but install_sync just passes it through to the
  // install backend.
  std::fs::write(&key_path, "PRIVATE-KEY-PEM").unwrap();

  let audit: Arc<dyn AuditStore> = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap());
  let cluster = Arc::new(FixedLeader::new(is_leader));

  let bundle = CertBackends {
    config: cert_config(cert_id, key_path),
    ca: Arc::new(StubCa) as Arc<dyn CABackend>,
    dcv: Arc::new(StubDcv) as Arc<dyn DcvBackend>,
    install: Some(Arc::clone(&install) as Arc<dyn InstallBackend>),
  };

  let task = InstallSyncTask::new(
    Arc::new(vec![bundle]),
    Arc::clone(&audit),
    Arc::clone(&cluster) as Arc<dyn ClusterCoordinator>,
    InstallSyncConfig {
      poll_interval: Duration::from_secs(60),
    },
  );
  (task, audit, cluster, install, tmp)
}

#[tokio::test]
async fn follower_installs_audit_cert_when_no_local_copy() {
  let install = Arc::new(RecordingInstall::new(None));
  let (task, audit, _cluster, install, _tmp) =
    build_task("from-audit", Arc::clone(&install), false).await;

  let pem = issue_pem(60);
  audit
    .record_issued_cert("from-audit", &pem, "CHAIN-PEM", chrono::Utc::now())
    .await
    .unwrap();

  task.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
  assert_eq!(
    install.last_installed_pem.lock().await.as_deref(),
    Some(pem.as_str())
  );
}

#[tokio::test]
async fn leader_skips_install_sync_entirely() {
  let install = Arc::new(RecordingInstall::new(None));
  let (task, audit, _cluster, install, _tmp) =
    build_task("leader-noop", Arc::clone(&install), true).await;

  audit
    .record_issued_cert("leader-noop", &issue_pem(60), "CHAIN", chrono::Utc::now())
    .await
    .unwrap();

  task.sweep().await;
  assert_eq!(
    install.install_calls.load(Ordering::SeqCst),
    0,
    "leader's renewer pipeline owns install; sync task is a no-op"
  );
}

#[tokio::test]
async fn follower_skips_when_local_cert_is_already_fresh() {
  // Local cert valid 90 days; audit cert valid 60 days. Local is
  // newer; skip install.
  let local = issue_pem(90);
  let install = Arc::new(RecordingInstall::new(Some(local)));
  let (task, audit, _cluster, install, _tmp) =
    build_task("already-fresh", Arc::clone(&install), false).await;

  audit
    .record_issued_cert("already-fresh", &issue_pem(60), "CHAIN", chrono::Utc::now())
    .await
    .unwrap();

  task.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn follower_installs_when_audit_cert_is_fresher_than_local() {
  let local = issue_pem(15);
  let audit_cert = issue_pem(60);
  let install = Arc::new(RecordingInstall::new(Some(local)));
  let (task, audit, _cluster, install, _tmp) =
    build_task("fresher-from-audit", Arc::clone(&install), false).await;

  audit
    .record_issued_cert(
      "fresher-from-audit",
      &audit_cert,
      "CHAIN",
      chrono::Utc::now(),
    )
    .await
    .unwrap();

  task.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn follower_skips_when_audit_has_no_cert() {
  let install = Arc::new(RecordingInstall::new(None));
  let (task, _audit, _cluster, install, _tmp) =
    build_task("never-issued", Arc::clone(&install), false).await;

  task.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn promotion_to_leader_quiets_install_sync() {
  let install = Arc::new(RecordingInstall::new(None));
  let (task, audit, cluster, install, _tmp) =
    build_task("promoted", Arc::clone(&install), false).await;

  audit
    .record_issued_cert("promoted", &issue_pem(60), "CHAIN", chrono::Utc::now())
    .await
    .unwrap();

  // Follower sweep installs.
  task.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);

  // Promote and sweep again: even with a fresh audit entry, the
  // sync task is a no-op on the leader. (We also write a new audit
  // cert to confirm the leader path is the gate, not the freshness
  // check.)
  cluster.is_leader.store(true, Ordering::Release);
  audit
    .record_issued_cert("promoted", &issue_pem(120), "CHAIN", chrono::Utc::now())
    .await
    .unwrap();
  task.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
}
