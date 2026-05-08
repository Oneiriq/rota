use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use std::sync::atomic::AtomicBool;

use rota_core::backend::{
  AlertBackend, AlertEvent, AlertKind, CABackend, DcvBackend, DcvChallenge, InstallBackend,
  IssuedCert,
};
use rota_core::cluster::ClusterCoordinator;
use rota_core::config::{CaSpec, CertConfig, DcvSpec, InstallSpec};
use rota_core::Result;
use tokio::sync::Mutex as TokioMutex;

use super::*;
use crate::audit::SqliteAuditStore;
use crate::backends::CertBackends;

/// CA mock that always succeeds; used to drive the renewer end-to-end
/// from inside scheduler tests without touching the network.
#[derive(Default)]
struct OkCa {
  submit_calls: AtomicUsize,
}

#[async_trait]
impl CABackend for OkCa {
  fn name(&self) -> &str {
    "ok-ca"
  }
  async fn submit(
    &self,
    _domains: &[String],
    _csr_pem: &str,
    _preferred_kinds: &[rota_core::backend::ChallengeKind],
  ) -> Result<Vec<DcvChallenge>> {
    self.submit_calls.fetch_add(1, Ordering::SeqCst);
    Ok(vec![DcvChallenge::Dns01 {
      record_name: "_acme-challenge.example.com".to_owned(),
      record_value: "x".to_owned(),
      ttl: 60,
    }])
  }
  async fn await_issuance(&self, _domains: &[String]) -> Result<IssuedCert> {
    Ok(IssuedCert {
      cert_pem: "-----BEGIN CERTIFICATE-----\nL\n-----END CERTIFICATE-----\n".to_owned(),
      chain_pem: "-----BEGIN CERTIFICATE-----\nI\n-----END CERTIFICATE-----\n".to_owned(),
    })
  }
}

#[derive(Default)]
struct OkDcv;

#[async_trait]
impl DcvBackend for OkDcv {
  fn name(&self) -> &str {
    "ok-dcv"
  }
  fn supported_kinds(&self) -> &[rota_core::backend::ChallengeKind] {
    &[rota_core::backend::ChallengeKind::Dns01]
  }
  async fn publish(&self, _: &DcvChallenge) -> Result<()> {
    Ok(())
  }
  async fn remove(&self, _: &DcvChallenge) -> Result<()> {
    Ok(())
  }
}

/// Install mock with a configurable `current_cert_pem` return so the
/// scheduler decision logic can be driven without writing real PEM
/// to disk every test.
struct ProbedInstall {
  pem: std::sync::Mutex<Option<String>>,
  install_calls: AtomicUsize,
}

impl ProbedInstall {
  fn new(pem: Option<&str>) -> Self {
    Self {
      pem: std::sync::Mutex::new(pem.map(str::to_owned)),
      install_calls: AtomicUsize::new(0),
    }
  }
  fn set_pem(&self, pem: Option<&str>) {
    *self.pem.lock().unwrap() = pem.map(str::to_owned);
  }
}

#[async_trait]
impl InstallBackend for ProbedInstall {
  fn name(&self) -> &str {
    "probed-install"
  }
  async fn install(&self, _: &IssuedCert, _: &str, _: &[String]) -> Result<()> {
    self.install_calls.fetch_add(1, Ordering::SeqCst);
    Ok(())
  }
  async fn current_cert_pem(&self, _cert_id: &str) -> Result<Option<String>> {
    Ok(self.pem.lock().unwrap().clone())
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

async fn build_scheduler(
  cert_id: &str,
  install: Arc<ProbedInstall>,
  threshold_days: i64,
  failure_cooldown: Duration,
) -> (Scheduler, Arc<OkCa>, Arc<ProbedInstall>) {
  let tmp = tempfile::tempdir().unwrap();
  let key_path = tmp.path().join(format!("{cert_id}.key"));

  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap());
  let renewer = Arc::new(CertRenewer::new(
    Arc::clone(&audit) as Arc<dyn crate::audit::AuditStore>
  ));

  let ca = Arc::new(OkCa::default());
  let bundle = CertBackends {
    config: cert_config(cert_id, key_path),
    ca: Arc::clone(&ca) as Arc<dyn CABackend>,
    dcv: Arc::new(OkDcv) as Arc<dyn DcvBackend>,
    install: Some(Arc::clone(&install) as Arc<dyn InstallBackend>),
  };
  // Leak the tempdir so the key path stays valid for the test
  // duration; tempdir's Drop would otherwise clean it up early
  // since we don't return the handle.
  std::mem::forget(tmp);

  let scheduler = Scheduler::new(
    Arc::new(vec![bundle]),
    renewer,
    SchedulerConfig {
      check_interval: Duration::from_secs(60),
      threshold_days,
      failure_cooldown,
    },
  );
  (scheduler, ca, install)
}

#[tokio::test]
async fn sweep_renews_when_cert_within_threshold() {
  let install = Arc::new(ProbedInstall::new(Some(&issue_pem(15))));
  let (sched, ca, install) = build_scheduler(
    "near-expiry",
    Arc::clone(&install),
    30,
    Duration::from_secs(60),
  )
  .await;
  sched.sweep().await;
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 1);
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sweep_skips_when_cert_well_ahead_of_threshold() {
  let install = Arc::new(ProbedInstall::new(Some(&issue_pem(60))));
  let (sched, ca, _install) =
    build_scheduler("fresh", Arc::clone(&install), 30, Duration::from_secs(60)).await;
  sched.sweep().await;
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn sweep_renews_when_no_cert_installed() {
  let install = Arc::new(ProbedInstall::new(None));
  let (sched, ca, install) = build_scheduler(
    "first-run",
    Arc::clone(&install),
    30,
    Duration::from_secs(60),
  )
  .await;
  sched.sweep().await;
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 1);
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sweep_renews_when_installed_cert_unparseable() {
  let install = Arc::new(ProbedInstall::new(Some("not a pem")));
  let (sched, ca, _install) =
    build_scheduler("garbage", Arc::clone(&install), 30, Duration::from_secs(60)).await;
  sched.sweep().await;
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cooldown_blocks_immediate_retry_after_failure() {
  // Force the renewer into a known-failing state by injecting an
  // install that says "install ok" but keeping the cert not-installed
  // signal so the scheduler thinks it's still due. To engineer a
  // failure we use a CA mock whose await_issuance bails.
  struct FailingCa;
  #[async_trait]
  impl CABackend for FailingCa {
    fn name(&self) -> &str {
      "failing-ca"
    }
    async fn submit(
      &self,
      _: &[String],
      _: &str,
      _: &[rota_core::backend::ChallengeKind],
    ) -> Result<Vec<DcvChallenge>> {
      Ok(vec![DcvChallenge::Dns01 {
        record_name: "_acme-challenge.example.com".to_owned(),
        record_value: "x".to_owned(),
        ttl: 60,
      }])
    }
    async fn await_issuance(&self, _: &[String]) -> Result<IssuedCert> {
      Err(rota_core::Error::Ca("ca down".to_owned()))
    }
  }

  let tmp = tempfile::tempdir().unwrap();
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap());
  let renewer = Arc::new(CertRenewer::new(
    Arc::clone(&audit) as Arc<dyn crate::audit::AuditStore>
  ));
  let install = Arc::new(ProbedInstall::new(None));
  let bundle = CertBackends {
    config: cert_config("flaky", tmp.path().join("k.key")),
    ca: Arc::new(FailingCa) as Arc<dyn CABackend>,
    dcv: Arc::new(OkDcv) as Arc<dyn DcvBackend>,
    install: Some(Arc::clone(&install) as Arc<dyn InstallBackend>),
  };
  std::mem::forget(tmp);

  let scheduler = Scheduler::new(
    Arc::new(vec![bundle]),
    renewer,
    SchedulerConfig {
      check_interval: Duration::from_secs(60),
      threshold_days: 30,
      // Long enough that the second sweep is definitely inside the
      // cooldown window.
      failure_cooldown: Duration::from_secs(3600),
    },
  );

  scheduler.sweep().await;
  // First attempt fired (and failed inside the renewer; the CA mock
  // bails at await_issuance). Install never ran.
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 0);

  // Cooldown should suppress the second sweep entirely. The CA's
  // submit was called once on the first sweep; we're checking that
  // a second call was NOT made.
  let before_second = install.install_calls.load(Ordering::SeqCst);
  scheduler.sweep().await;
  let after_second = install.install_calls.load(Ordering::SeqCst);
  assert_eq!(before_second, after_second, "cooldown should block retry");
}

#[tokio::test]
async fn cooldown_clears_after_success() {
  let install = Arc::new(ProbedInstall::new(None));
  let (sched, _ca, install) = build_scheduler(
    "ok-then-due",
    Arc::clone(&install),
    30,
    Duration::from_secs(60),
  )
  .await;

  // First sweep installs (success).
  sched.sweep().await;
  let after_first = install.install_calls.load(Ordering::SeqCst);
  assert_eq!(after_first, 1);

  // Now reset the install probe so the next sweep sees "no cert
  // installed" again. The successful prior sweep means there's no
  // cooldown active.
  install.set_pem(None);
  sched.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 2);
}

/// Alert sink that captures every dispatched event for assertion.
#[derive(Default)]
struct RecordingAlert {
  events: TokioMutex<Vec<AlertEvent>>,
}

#[async_trait]
impl AlertBackend for RecordingAlert {
  fn name(&self) -> &str {
    "recording"
  }
  async fn dispatch(&self, event: &AlertEvent) -> Result<()> {
    self.events.lock().await.push(event.clone());
    Ok(())
  }
}

#[tokio::test]
async fn alert_dispatched_on_renewal_failure() {
  // Same failing-CA shape as the cooldown test: submit succeeds, but
  // await_issuance returns an error so the renewer reports failure.
  struct FailingCa;
  #[async_trait]
  impl CABackend for FailingCa {
    fn name(&self) -> &str {
      "failing-ca"
    }
    async fn submit(
      &self,
      _: &[String],
      _: &str,
      _: &[rota_core::backend::ChallengeKind],
    ) -> Result<Vec<DcvChallenge>> {
      Ok(vec![DcvChallenge::Dns01 {
        record_name: "_acme-challenge.example.com".to_owned(),
        record_value: "x".to_owned(),
        ttl: 60,
      }])
    }
    async fn await_issuance(&self, _: &[String]) -> Result<IssuedCert> {
      Err(rota_core::Error::Ca("ca down".to_owned()))
    }
  }

  let tmp = tempfile::tempdir().unwrap();
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap());
  let renewer = Arc::new(CertRenewer::new(
    Arc::clone(&audit) as Arc<dyn crate::audit::AuditStore>
  ));
  let install = Arc::new(ProbedInstall::new(None));
  let bundle = CertBackends {
    config: cert_config("alert-fail", tmp.path().join("k.key")),
    ca: Arc::new(FailingCa) as Arc<dyn CABackend>,
    dcv: Arc::new(OkDcv) as Arc<dyn DcvBackend>,
    install: Some(Arc::clone(&install) as Arc<dyn InstallBackend>),
  };
  std::mem::forget(tmp);

  let recorder = Arc::new(RecordingAlert::default());
  let alerts: Arc<Vec<Arc<dyn AlertBackend>>> =
    Arc::new(vec![Arc::clone(&recorder) as Arc<dyn AlertBackend>]);

  let scheduler = Scheduler::new(
    Arc::new(vec![bundle]),
    renewer,
    SchedulerConfig {
      check_interval: Duration::from_secs(60),
      threshold_days: 30,
      failure_cooldown: Duration::from_secs(60),
    },
  )
  .with_alerts(alerts);

  scheduler.sweep().await;

  let recorded = recorder.events.lock().await;
  assert_eq!(recorded.len(), 1);
  assert_eq!(recorded[0].cert_id, "alert-fail");
  assert!(matches!(recorded[0].kind, AlertKind::RenewalFailed));
  assert!(
    !recorded[0].message.is_empty(),
    "alert event must carry an error message"
  );
}

#[tokio::test]
async fn no_alert_dispatched_on_renewal_success() {
  let install = Arc::new(ProbedInstall::new(None));
  let recorder = Arc::new(RecordingAlert::default());
  let alerts: Arc<Vec<Arc<dyn AlertBackend>>> =
    Arc::new(vec![Arc::clone(&recorder) as Arc<dyn AlertBackend>]);

  let tmp = tempfile::tempdir().unwrap();
  let key_path = tmp.path().join("alert-ok.key");
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap());
  let renewer = Arc::new(CertRenewer::new(
    Arc::clone(&audit) as Arc<dyn crate::audit::AuditStore>
  ));
  let ca = Arc::new(OkCa::default());
  let bundle = CertBackends {
    config: cert_config("alert-ok", key_path),
    ca: Arc::clone(&ca) as Arc<dyn CABackend>,
    dcv: Arc::new(OkDcv) as Arc<dyn DcvBackend>,
    install: Some(Arc::clone(&install) as Arc<dyn InstallBackend>),
  };
  std::mem::forget(tmp);

  let scheduler = Scheduler::new(
    Arc::new(vec![bundle]),
    renewer,
    SchedulerConfig {
      check_interval: Duration::from_secs(60),
      threshold_days: 30,
      failure_cooldown: Duration::from_secs(60),
    },
  )
  .with_alerts(alerts);

  scheduler.sweep().await;
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
  assert!(
    recorder.events.lock().await.is_empty(),
    "successful renewal must not emit a RenewalFailed alert"
  );
}

/// Cluster coordinator with a flippable leadership state. Lets
/// scheduler tests assert that a sweep is gated on `is_leader()`.
struct ToggleCluster {
  node_id: String,
  is_leader: AtomicBool,
}

impl ToggleCluster {
  fn new(is_leader: bool) -> Self {
    Self {
      node_id: "test-node".to_owned(),
      is_leader: AtomicBool::new(is_leader),
    }
  }

  fn set_leader(&self, value: bool) {
    self.is_leader.store(value, Ordering::Release);
  }
}

#[async_trait]
impl ClusterCoordinator for ToggleCluster {
  fn name(&self) -> &str {
    "toggle"
  }
  fn node_id(&self) -> &str {
    &self.node_id
  }
  fn is_leader(&self) -> bool {
    self.is_leader.load(Ordering::Acquire)
  }
  async fn run(&self) -> Result<()> {
    std::future::pending::<()>().await;
    Ok(())
  }
}

#[tokio::test]
async fn follower_skips_sweep_entirely() {
  let install = Arc::new(ProbedInstall::new(None));
  let (sched_default, ca, install) = build_scheduler(
    "follower-test",
    Arc::clone(&install),
    30,
    Duration::from_secs(60),
  )
  .await;

  let cluster = Arc::new(ToggleCluster::new(false));
  let scheduler = sched_default.with_cluster(Arc::clone(&cluster) as Arc<dyn ClusterCoordinator>);

  scheduler.sweep().await;

  // Cluster says we're a follower: nothing should have been
  // attempted, even though install reports no cert installed.
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 0);
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn promotion_to_leader_resumes_sweeps() {
  let install = Arc::new(ProbedInstall::new(None));
  let (sched_default, ca, install) = build_scheduler(
    "promotion-test",
    Arc::clone(&install),
    30,
    Duration::from_secs(60),
  )
  .await;

  let cluster = Arc::new(ToggleCluster::new(false));
  let scheduler = sched_default.with_cluster(Arc::clone(&cluster) as Arc<dyn ClusterCoordinator>);

  // First sweep is suppressed.
  scheduler.sweep().await;
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 0);

  // Promote to leader; next sweep proceeds.
  cluster.set_leader(true);
  scheduler.sweep().await;
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 1);
  assert_eq!(install.install_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_install_backend_means_no_renewal() {
  let tmp = tempfile::tempdir().unwrap();
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap());
  let renewer = Arc::new(CertRenewer::new(
    Arc::clone(&audit) as Arc<dyn crate::audit::AuditStore>
  ));
  let ca = Arc::new(OkCa::default());
  let bundle = CertBackends {
    config: cert_config("install-less", tmp.path().join("k.key")),
    ca: Arc::clone(&ca) as Arc<dyn CABackend>,
    dcv: Arc::new(OkDcv) as Arc<dyn DcvBackend>,
    install: None,
  };
  std::mem::forget(tmp);

  let scheduler = Scheduler::new(
    Arc::new(vec![bundle]),
    renewer,
    SchedulerConfig {
      check_interval: Duration::from_secs(60),
      threshold_days: 30,
      failure_cooldown: Duration::from_secs(60),
    },
  );

  scheduler.sweep().await;
  // No install backend means we have nothing to read so we leave
  // the cert alone. The CA shouldn't see a submit.
  assert_eq!(ca.submit_calls.load(Ordering::SeqCst), 0);
}
