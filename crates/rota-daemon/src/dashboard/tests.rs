use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use rota_core::backend::{CABackend, DcvChallenge, InstallBackend, IssuedCert, RegistrarBackend};
use rota_core::config::{CaSpec, CertConfig, InstallSpec, RegistrarSpec};
use rota_core::Result;
use tower::ServiceExt;

use super::*;
use crate::audit::SqliteAuditStore;
use crate::backends::CertBackends;

#[derive(Default)]
struct StubCa;
#[async_trait]
impl CABackend for StubCa {
  fn name(&self) -> &str {
    "ca"
  }
  async fn submit(&self, _: &[String], _: &str) -> Result<Vec<DcvChallenge>> {
    unreachable!()
  }
  async fn await_issuance(&self, _: &[String]) -> Result<IssuedCert> {
    unreachable!()
  }
}

#[derive(Default)]
struct StubRegistrar;
#[async_trait]
impl RegistrarBackend for StubRegistrar {
  fn name(&self) -> &str {
    "reg"
  }
  async fn publish_txt(&self, _: &DcvChallenge) -> Result<()> {
    unreachable!()
  }
  async fn remove_txt(&self, _: &DcvChallenge) -> Result<()> {
    unreachable!()
  }
}

#[derive(Default)]
struct StubInstall;
#[async_trait]
impl InstallBackend for StubInstall {
  fn name(&self) -> &str {
    "install"
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
    description: "demo cert".to_owned(),
    domains: vec!["example.com".to_owned()],
    key_path: PathBuf::from("/tmp/unused"),
    ca: CaSpec::Namecheap { ssl_id: 1 },
    registrar: RegistrarSpec::Namecheap,
    install: InstallSpec::Filesystem {
      directory: PathBuf::from("/tmp/unused"),
    },
  }
}

async fn build_router_state() -> DashboardState {
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap()) as Arc<dyn AuditStore>;
  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let bundles = Arc::new(vec![CertBackends {
    config: cert_config("alpha"),
    ca: Arc::new(StubCa) as Arc<dyn CABackend>,
    registrar: Arc::new(StubRegistrar) as Arc<dyn RegistrarBackend>,
    install: Some(Arc::new(StubInstall) as Arc<dyn InstallBackend>),
  }]);
  DashboardState {
    bundles,
    audit,
    renewer,
  }
}

fn router(state: DashboardState) -> Router {
  Router::new()
    .route("/", get(super::index))
    .route("/cert/:id", get(super::cert_detail))
    .with_state(state)
}

async fn body_string(resp: axum::response::Response) -> String {
  let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
    .await
    .unwrap();
  String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn index_lists_configured_certs() {
  let state = build_router_state().await;
  let app = router(state);
  let resp = app
    .oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(resp.status(), StatusCode::OK);
  let body = body_string(resp).await;
  assert!(body.contains("alpha"));
  assert!(body.contains("example.com"));
  // Header link to cert detail page is present.
  assert!(body.contains(r#"href="/cert/alpha""#));
}

#[tokio::test]
async fn cert_detail_returns_200_for_known_cert() {
  let state = build_router_state().await;
  let app = router(state);
  let resp = app
    .oneshot(
      HttpRequest::builder()
        .uri("/cert/alpha")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(resp.status(), StatusCode::OK);
  let body = body_string(resp).await;
  assert!(body.contains("alpha"));
  assert!(body.contains("demo cert"));
  assert!(body.contains("renew now"));
}

#[tokio::test]
async fn cert_detail_returns_404_for_unknown_cert() {
  let state = build_router_state().await;
  let app = router(state);
  let resp = app
    .oneshot(
      HttpRequest::builder()
        .uri("/cert/missing")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(resp.status(), StatusCode::NOT_FOUND);
  let body = body_string(resp).await;
  assert!(body.contains("unknown cert"));
}

#[tokio::test]
async fn empty_dashboard_says_no_certs() {
  let audit = Arc::new(SqliteAuditStore::open_in_memory().await.unwrap()) as Arc<dyn AuditStore>;
  let renewer = Arc::new(CertRenewer::new(Arc::clone(&audit)));
  let state = DashboardState {
    bundles: Arc::new(vec![]),
    audit,
    renewer,
  };
  let app = router(state);
  let resp = app
    .oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(resp.status(), StatusCode::OK);
  let body = body_string(resp).await;
  assert!(body.contains("no certs configured"));
}
