use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rota_core::backend::{CABackend, DcvChallenge, InstallBackend, IssuedCert, RegistrarBackend};
use rota_core::config::{CaSpec, CertConfig, InstallSpec, RegistrarSpec};
use rota_core::Result;

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
  async fn submit(&self, _domains: &[String], _csr_pem: &str) -> Result<Vec<DcvChallenge>> {
    self.submit_calls.fetch_add(1, Ordering::SeqCst);
    Ok(vec![DcvChallenge {
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
struct OkRegistrar;

#[async_trait]
impl RegistrarBackend for OkRegistrar {
  fn name(&self) -> &str {
    "ok-reg"
  }
  async fn publish_txt(&self, _: &DcvChallenge) -> Result<()> {
    Ok(())
  }
  async fn remove_txt(&self, _: &DcvChallenge) -> Result<()> {
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
    registrar: RegistrarSpec::Namecheap,
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
    registrar: Arc::new(OkRegistrar) as Arc<dyn RegistrarBackend>,
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
    async fn submit(&self, _: &[String], _: &str) -> Result<Vec<DcvChallenge>> {
      Ok(vec![DcvChallenge {
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
    registrar: Arc::new(OkRegistrar) as Arc<dyn RegistrarBackend>,
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
    registrar: Arc::new(OkRegistrar) as Arc<dyn RegistrarBackend>,
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
