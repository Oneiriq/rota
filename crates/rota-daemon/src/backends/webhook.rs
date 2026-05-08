//! HTTPS webhook alert backend.
//!
//! POSTs one JSON envelope per event to the configured URL:
//!
//! ```json
//! {
//!   "cert_id": "example-public",
//!   "kind": "renewal_failed",
//!   "message": "ca down",
//!   "timestamp": "2026-05-07T14:00:00.000Z"
//! }
//! ```
//!
//! The shape is intentionally vendor-neutral. Slack-incoming, Discord,
//! Microsoft Teams, and similar opinionated formats are out of scope:
//! point a small relay (n8n, Pipedream, your own service) at this
//! webhook and translate. Keeping rota's wire format flat avoids a
//! per-vendor bestiary inside the daemon.
//!
//! Auth is optional Bearer token loaded from a file at startup. Other
//! schemes (basic auth, signed payloads) can layer on if real-world
//! demand surfaces.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use rota_core::backend::{AlertBackend, AlertEvent};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use serde_json::json;
use tracing::info;

const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[derive(Clone)]
pub struct WebhookAlert {
  http: Client,
  url: String,
  bearer_token: Option<String>,
}

impl std::fmt::Debug for WebhookAlert {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WebhookAlert")
      .field("url", &self.url)
      .field(
        "bearer_token",
        &self.bearer_token.as_ref().map(|_| "<redacted>"),
      )
      .finish_non_exhaustive()
    }
}

pub struct WebhookAlertParams<'a> {
  pub url: &'a str,
  pub bearer_token: Option<&'a str>,
  pub timeout: Option<Duration>,
}

impl WebhookAlert {
  pub fn new(params: WebhookAlertParams<'_>) -> Result<Self> {
    if params.url.is_empty() {
      return Err(Error::ConfigInvalid(
        "webhook alert config requires a non-empty `url`".into(),
      ));
    }
    if !params.url.starts_with("http://") && !params.url.starts_with("https://") {
      return Err(Error::ConfigInvalid(format!(
        "webhook alert `url` must start with http:// or https://, got: {}",
        params.url
      )));
    }

    let timeout = params
      .timeout
      .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    let http = Client::builder()
      .timeout(timeout)
      .build()
      .map_err(|e| Error::Alert(format!("webhook http client: {e}")))?;

    Ok(Self {
      http,
      url: params.url.to_owned(),
      bearer_token: params.bearer_token.map(str::to_owned),
    })
  }
}

#[async_trait]
impl AlertBackend for WebhookAlert {
  fn name(&self) -> &str {
    "webhook"
  }

  async fn dispatch(&self, event: &AlertEvent) -> Result<()> {
    let body = json!({
      "cert_id": event.cert_id,
      "kind": event.kind.as_str(),
      "message": event.message,
      "timestamp": event.timestamp.to_rfc3339(),
    });

    let mut req = self.http.post(&self.url).json(&body);
    if let Some(token) = &self.bearer_token {
      req = req.bearer_auth(token);
    }

    let resp = req
      .send()
      .await
      .map_err(|e| Error::Alert(format!("webhook http: {}", redact(&e.to_string()))))?;

    let status = resp.status();
    if !status.is_success() {
      let body = resp.text().await.unwrap_or_default();
      return Err(Error::Alert(format!(
        "webhook http {status}: {}",
        redact(&body)
      )));
    }

    info!(
      cert = %event.cert_id,
      kind = event.kind.as_str(),
      "webhook alert dispatched"
    );
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use chrono::Utc;
  use rota_core::backend::AlertKind;

  fn ev() -> AlertEvent {
    AlertEvent {
      cert_id: "example-public".to_owned(),
      kind: AlertKind::RenewalFailed,
      message: "ca down".to_owned(),
      timestamp: Utc::now(),
    }
  }

  #[test]
  fn rejects_empty_url() {
    let err = WebhookAlert::new(WebhookAlertParams {
      url: "",
      bearer_token: None,
      timeout: None,
    })
    .expect_err("empty url must fail");
    assert!(err.to_string().contains("non-empty"), "got: {err}");
  }

  #[test]
  fn rejects_non_http_url() {
    let err = WebhookAlert::new(WebhookAlertParams {
      url: "ftp://example.com/hook",
      bearer_token: None,
      timeout: None,
    })
    .expect_err("non-http url must fail");
    assert!(err.to_string().contains("http://"), "got: {err}");
  }

  #[test]
  fn debug_does_not_leak_bearer_token() {
    let alert = WebhookAlert::new(WebhookAlertParams {
      url: "https://example.com/hook",
      bearer_token: Some("supersecrettoken"),
      timeout: None,
    })
    .unwrap();
    let dbg = format!("{alert:?}");
    assert!(
      !dbg.contains("supersecrettoken"),
      "debug repr leaked bearer: {dbg}"
    );
  }

  #[tokio::test]
  async fn posts_envelope_to_local_server() {
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct Captured {
      body: Option<serde_json::Value>,
      auth: Option<String>,
    }

    let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
    let captured_for_handler = Arc::clone(&captured);

    let app = Router::new().route(
      "/hook",
      post(
        move |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| {
          let captured = Arc::clone(&captured_for_handler);
          async move {
            let mut c = captured.lock().await;
            c.body = Some(body);
            c.auth = headers
              .get("authorization")
              .and_then(|v| v.to_str().ok())
              .map(str::to_owned);
            axum::http::StatusCode::OK
          }
        },
      ),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
      axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{addr}/hook");
    let alert = WebhookAlert::new(WebhookAlertParams {
      url: &url,
      bearer_token: Some("tok123"),
      timeout: Some(Duration::from_secs(5)),
    })
    .unwrap();

    alert.dispatch(&ev()).await.unwrap();

    let c = captured.lock().await;
    let body = c.body.as_ref().expect("server did not receive body");
    assert_eq!(body["cert_id"], "example-public");
    assert_eq!(body["kind"], "renewal_failed");
    assert_eq!(body["message"], "ca down");
    assert!(body["timestamp"].is_string());

    let auth = c.auth.as_ref().expect("missing auth header");
    assert_eq!(auth, "Bearer tok123");

    server.abort();
  }

  #[tokio::test]
  async fn surfaces_non_2xx_as_error() {
    use axum::routing::post;
    use axum::Router;

    let app = Router::new().route(
      "/hook",
      post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
      axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{addr}/hook");
    let alert = WebhookAlert::new(WebhookAlertParams {
      url: &url,
      bearer_token: None,
      timeout: Some(Duration::from_secs(5)),
    })
    .unwrap();

    let err = alert.dispatch(&ev()).await.expect_err("500 must error");
    assert!(err.to_string().contains("500"), "got: {err}");
    server.abort();
  }
}
