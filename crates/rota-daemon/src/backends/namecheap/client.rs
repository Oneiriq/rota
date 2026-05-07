//! Shared HTTP client for the Namecheap API.
//!
//! Namecheap's API is XML-over-HTTPS with auth carried in query
//! string params (no headers). All commands hit the same endpoint
//! and discriminate on `Command=<method.name>`. The wrapper here
//! injects auth params consistently and surfaces a typed error when
//! `Status="ERROR"` comes back in the response envelope.

use std::sync::Arc;

use reqwest::Client;
use rota_core::{Error, Result};
use tracing::debug;

use super::xml::{parse_response, ApiResponse};

/// Production endpoint. Sandbox is `https://api.sandbox.namecheap.com/xml.response`
/// — wire it in alongside the first integration test that needs it.
const PRODUCTION_ENDPOINT: &str = "https://api.namecheap.com/xml.response";

/// Authentication material the Namecheap API requires on every call.
///
/// `client_ip` must match an entry on the account's "Whitelisted IPs"
/// list — Namecheap rejects the request otherwise.
#[derive(Debug, Clone)]
pub struct NamecheapCreds {
  pub api_user: String,
  pub api_key: String,
  pub username: String,
  pub client_ip: String,
}

#[derive(Debug, Clone)]
pub struct NamecheapClient {
  http: Client,
  creds: NamecheapCreds,
  endpoint: &'static str,
}

impl NamecheapClient {
  /// New production-endpoint client.
  pub fn new(creds: NamecheapCreds) -> Self {
    Self {
      http: Client::new(),
      creds,
      endpoint: PRODUCTION_ENDPOINT,
    }
  }

  /// Convenience for sharing a single client across the CA + registrar
  /// without forcing callers to wrap twice.
  pub fn into_arc(self) -> Arc<Self> {
    Arc::new(self)
  }

  /// Run a Namecheap command. `extra_params` carries the
  /// command-specific arguments; auth params are added here so every
  /// call site stays declarative.
  pub async fn call<P>(&self, command: &str, extra_params: P) -> Result<ApiResponse>
  where
    P: IntoIterator<Item = (&'static str, String)>,
  {
    let mut params: Vec<(&str, String)> = vec![
      ("ApiUser", self.creds.api_user.clone()),
      ("ApiKey", self.creds.api_key.clone()),
      ("UserName", self.creds.username.clone()),
      ("ClientIp", self.creds.client_ip.clone()),
      ("Command", command.to_owned()),
    ];
    params.extend(extra_params);

    debug!(command, "namecheap api call");
    let resp = self
      .http
      .get(self.endpoint)
      .query(&params)
      .send()
      .await
      .map_err(|e| Error::Ca(format!("namecheap http: {e}")))?;

    let body = resp
      .text()
      .await
      .map_err(|e| Error::Ca(format!("namecheap body: {e}")))?;

    parse_response(&body)
  }
}
