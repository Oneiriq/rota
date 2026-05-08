//! Cloudflare DNS-01 DCV backend (v4 API, Bearer-token auth).
//!
//! Three steps per `publish`:
//!
//! 1. Resolve the apex zone for the record name (`_acme-challenge.x.example.com` -> zone `example.com`).
//! 2. Look for an existing TXT record with the same name + value to
//!    keep `publish` idempotent (matches the trait contract).
//! 3. POST the record if absent.
//!
//! `remove` mirrors the lookup + delete shape. Unlike Namecheap,
//! Cloudflare is per-record edit, so we don't have to read every
//! record on the zone first; the get-merge-set pattern is namecheap
//! specific.
//!
//! Token scopes: `Zone.DNS:Edit` on every zone rota will manage. The
//! older Global API Key works too but rota only supports tokens
//! because they cap blast radius if the secrets file leaks.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use rota_core::backend::{ChallengeKind, DcvBackend, DcvChallenge};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const TXT_TTL_FALLBACK: u32 = 60;

#[derive(Clone)]
pub struct CloudflareClient {
  http: Client,
  api_token: String,
  base: String,
}

impl std::fmt::Debug for CloudflareClient {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CloudflareClient")
      .field("api_token", &"<redacted>")
      .field("base", &self.base)
      .finish_non_exhaustive()
  }
}

impl CloudflareClient {
  pub fn new(api_token: String) -> Self {
    Self {
      http: Client::new(),
      api_token,
      base: API_BASE.to_owned(),
    }
  }

  /// Override the API base URL. Public so tests can point at a
  /// local mock server.
  pub fn with_base(mut self, base: String) -> Self {
    self.base = base;
    self
  }

  pub fn into_arc(self) -> Arc<Self> {
    Arc::new(self)
  }

  fn auth_headers(&self) -> Result<HeaderMap> {
    let mut h = HeaderMap::new();
    h.insert(
      AUTHORIZATION,
      HeaderValue::from_str(&format!("Bearer {}", self.api_token))
        .map_err(|e| Error::Registrar(format!("auth header: {e}")))?,
    );
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(h)
  }

  async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
    let url = format!("{}{path}", self.base);
    debug!(url, "cloudflare GET");
    let resp = self
      .http
      .get(&url)
      .headers(self.auth_headers()?)
      .send()
      .await
      .map_err(|e| Error::Registrar(format!("cloudflare http: {}", redact(&e.to_string()))))?;
    decode_response(resp).await
  }

  async fn post<T: for<'de> Deserialize<'de>>(
    &self,
    path: &str,
    body: serde_json::Value,
  ) -> Result<T> {
    let url = format!("{}{path}", self.base);
    debug!(url, "cloudflare POST");
    let resp = self
      .http
      .post(&url)
      .headers(self.auth_headers()?)
      .json(&body)
      .send()
      .await
      .map_err(|e| Error::Registrar(format!("cloudflare http: {}", redact(&e.to_string()))))?;
    decode_response(resp).await
  }

  async fn delete<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
    let url = format!("{}{path}", self.base);
    debug!(url, "cloudflare DELETE");
    let resp = self
      .http
      .delete(&url)
      .headers(self.auth_headers()?)
      .send()
      .await
      .map_err(|e| Error::Registrar(format!("cloudflare http: {}", redact(&e.to_string()))))?;
    decode_response(resp).await
  }
}

async fn decode_response<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T> {
  let status = resp.status();
  let body = resp
    .text()
    .await
    .map_err(|e| Error::Registrar(format!("cloudflare body: {}", redact(&e.to_string()))))?;
  if !status.is_success() {
    return Err(Error::Registrar(format!(
      "cloudflare http {status}: {}",
      redact(&body)
    )));
  }
  let parsed: ApiResponse<T> = serde_json::from_str(&body)
    .map_err(|e| Error::Registrar(format!("cloudflare json: {e} (body: {body})")))?;
  if !parsed.success {
    let msgs = parsed
      .errors
      .into_iter()
      .map(|e| format!("{}: {}", e.code, e.message))
      .collect::<Vec<_>>()
      .join("; ");
    return Err(Error::Registrar(format!("cloudflare api error: {msgs}")));
  }
  parsed
    .result
    .ok_or_else(|| Error::Registrar("cloudflare response missing result block".into()))
}

#[derive(Debug, Clone)]
pub struct CloudflareDcv {
  client: Arc<CloudflareClient>,
}

impl CloudflareDcv {
  pub fn new(client: Arc<CloudflareClient>) -> Self {
    Self { client }
  }
}

const SUPPORTED: &[ChallengeKind] = &[ChallengeKind::Dns01];

#[async_trait]
impl DcvBackend for CloudflareDcv {
  fn name(&self) -> &str {
    "cloudflare"
  }

  fn supported_kinds(&self) -> &[ChallengeKind] {
    SUPPORTED
  }

  async fn publish(&self, challenge: &DcvChallenge) -> Result<()> {
    let DcvChallenge::Dns01 {
      record_name,
      record_value,
      ttl,
    } = challenge
    else {
      return Err(Error::Registrar(format!(
        "cloudflare dcv only supports dns-01, got {}",
        challenge.kind_str()
      )));
    };
    let zone_id = self.find_zone_id(record_name).await?;

    if self
      .find_matching_record(&zone_id, record_name, record_value)
      .await?
      .is_some()
    {
      debug!(record = %record_name, "cloudflare txt already present");
      return Ok(());
    }

    let body = json!({
      "type": "TXT",
      "name": record_name,
      "content": record_value,
      "ttl": (*ttl).max(TXT_TTL_FALLBACK),
    });
    let _: DnsRecordResponse = self
      .client
      .post(&format!("/zones/{zone_id}/dns_records"), body)
      .await?;
    info!(record = %record_name, "cloudflare publishing dcv txt");
    Ok(())
  }

  async fn remove(&self, challenge: &DcvChallenge) -> Result<()> {
    let DcvChallenge::Dns01 {
      record_name,
      record_value,
      ..
    } = challenge
    else {
      return Err(Error::Registrar(format!(
        "cloudflare dcv only supports dns-01, got {}",
        challenge.kind_str()
      )));
    };
    let zone_id = self.find_zone_id(record_name).await?;
    let Some(record_id) = self
      .find_matching_record(&zone_id, record_name, record_value)
      .await?
    else {
      // Idempotent: nothing to delete.
      return Ok(());
    };
    let _: DeletedRecord = self
      .client
      .delete(&format!("/zones/{zone_id}/dns_records/{record_id}"))
      .await?;
    info!(record = %record_name, "cloudflare removed dcv txt");
    Ok(())
  }
}

impl CloudflareDcv {
  /// Walk down the FQDN labels until Cloudflare reports a zone for
  /// the prefix. `_acme-challenge.api.example.com` tries
  /// `_acme-challenge.api.example.com`, then `api.example.com`,
  /// then `example.com`. The first match wins; this matches how
  /// every other ACME / DNS-01 client resolves zone-vs-subdomain.
  async fn find_zone_id(&self, record_name: &str) -> Result<String> {
    let candidates = zone_candidates(record_name);
    for candidate in &candidates {
      let zones: Vec<Zone> = self
        .client
        .get(&format!("/zones?name={candidate}&status=active"))
        .await?;
      if let Some(z) = zones.into_iter().next() {
        debug!(record = %record_name, zone = %candidate, "cloudflare zone resolved");
        return Ok(z.id);
      }
    }
    Err(Error::Registrar(format!(
      "no cloudflare zone matches {record_name} (tried: {})",
      candidates.join(", ")
    )))
  }

  async fn find_matching_record(
    &self,
    zone_id: &str,
    name: &str,
    value: &str,
  ) -> Result<Option<String>> {
    let records: Vec<DnsRecord> = self
      .client
      .get(&format!(
        "/zones/{zone_id}/dns_records?type=TXT&name={name}"
      ))
      .await?;
    Ok(
      records
        .into_iter()
        .find(|r| r.content.trim_matches('"') == value)
        .map(|r| r.id),
    )
  }
}

/// `_acme-challenge.api.dashboard.example.com` ->
/// `["_acme-challenge.api.dashboard.example.com", "api.dashboard.example.com",
///   "dashboard.example.com", "example.com"]`. We stop at two-label
/// candidates; trying TLDs (`com`) is pointless.
fn zone_candidates(record_name: &str) -> Vec<String> {
  let trimmed = record_name.trim_end_matches('.');
  let parts: Vec<&str> = trimmed.split('.').collect();
  let mut out = Vec::new();
  for i in 0..parts.len().saturating_sub(1) {
    out.push(parts[i..].join("."));
  }
  out
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiResponse<T> {
  success: bool,
  #[serde(default)]
  errors: Vec<ApiError>,
  result: Option<T>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiError {
  code: u32,
  message: String,
}

#[derive(Debug, Deserialize)]
struct Zone {
  id: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
  id: String,
  #[serde(default)]
  content: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecordResponse {
  #[allow(dead_code)]
  id: String,
}

#[derive(Debug, Deserialize)]
struct DeletedRecord {
  #[allow(dead_code)]
  id: String,
}

#[cfg(test)]
mod tests;
