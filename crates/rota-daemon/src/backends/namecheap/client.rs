//! Shared HTTP client for the Namecheap API.
//!
//! Namecheap's API is XML-over-HTTPS with auth carried in query
//! string params (no headers). All commands hit the same endpoint
//! and discriminate on `Command=<method.name>`. The wrapper here
//! injects auth params consistently and surfaces a typed error when
//! `Status="ERROR"` comes back in the response envelope.

use std::fmt;
use std::sync::Arc;

use reqwest::Client;
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use tracing::debug;

use super::xml::{parse_response, ApiResponse};

/// Production endpoint. Sandbox is `https://api.sandbox.namecheap.com/xml.response`;
/// wire it in alongside the first integration test that needs it.
const PRODUCTION_ENDPOINT: &str = "https://api.namecheap.com/xml.response";

/// Authentication material the Namecheap API requires on every call.
///
/// `client_ip` must match an entry on the account's "Whitelisted IPs"
/// list, or Namecheap rejects the request.
///
/// `Debug` is implemented manually so the api key never leaks through
/// `dbg!`, `panic!("{:?}", ...)`, or tracing's `?` shorthand. Don't
/// re-derive `Debug` here without thinking about the consequences.
#[derive(Clone)]
pub struct NamecheapCreds {
  pub api_user: String,
  pub api_key: String,
  pub username: String,
  pub client_ip: String,
}

impl fmt::Debug for NamecheapCreds {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("NamecheapCreds")
      .field("api_user", &self.api_user)
      .field("api_key", &"<redacted>")
      .field("username", &self.username)
      .field("client_ip", &self.client_ip)
      .finish()
  }
}

#[derive(Clone)]
pub struct NamecheapClient {
  http: Client,
  creds: NamecheapCreds,
  endpoint: &'static str,
}

impl fmt::Debug for NamecheapClient {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("NamecheapClient")
      .field("creds", &self.creds)
      .field("endpoint", &self.endpoint)
      .finish_non_exhaustive()
  }
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
      .map_err(|e| Error::Ca(format!("namecheap http: {}", redact(&e.to_string()))))?;

    let body = resp
      .text()
      .await
      .map_err(|e| Error::Ca(format!("namecheap body: {}", redact(&e.to_string()))))?;

    parse_response(&body)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn debug_repr_redacts_api_key() {
    let creds = NamecheapCreds {
      api_user: "alice".to_owned(),
      api_key: "deadbeefcafef00d".to_owned(),
      username: "alice".to_owned(),
      client_ip: "203.0.113.1".to_owned(),
    };
    let debug = format!("{creds:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("deadbeefcafef00d"));
  }

  #[test]
  fn client_debug_does_not_leak_creds() {
    let creds = NamecheapCreds {
      api_user: "alice".to_owned(),
      api_key: "topsecret123".to_owned(),
      username: "alice".to_owned(),
      client_ip: "203.0.113.1".to_owned(),
    };
    let client = NamecheapClient::new(creds);
    let debug = format!("{client:?}");
    assert!(!debug.contains("topsecret123"));
  }
}
