//! `namecheap.ssl.reissue` + `namecheap.ssl.getInfo` flow.
//!
//! v0.1 only handles **reissue** within an existing SSL subscription.
//! First-time activation is one-shot and Namecheap requires a long
//! list of admin contact fields that we don't want to model in the
//! config. Operators activate once by hand in Namecheap's UI; rota
//! handles every renewal after that.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rota_core::backend::{CABackend, ChallengeKind, DcvChallenge, IssuedCert};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use tracing::{debug, info, warn};

use super::client::NamecheapClient;

const POLL_INTERVAL: Duration = Duration::from_secs(30);
const POLL_DEADLINE: Duration = Duration::from_secs(60 * 30); // 30 min
const DCV_TTL_SECONDS: u32 = 300;

#[derive(Debug, Clone)]
pub struct NamecheapCa {
  client: Arc<NamecheapClient>,
  ssl_id: u64,
}

impl NamecheapCa {
  pub fn new(client: Arc<NamecheapClient>, ssl_id: u64) -> Self {
    Self { client, ssl_id }
  }

  async fn get_info(&self) -> Result<NamecheapCertInfo> {
    let resp = self
      .client
      .call(
        "namecheap.ssl.getInfo",
        [
          ("CertificateID", self.ssl_id.to_string()),
          ("Returncertificate", "true".to_owned()),
          ("Returntype", "Individual".to_owned()),
        ],
      )
      .await?;
    resp.ensure_ok()?;

    let status = resp
      .first_attribute("SSLStatus", "Status")
      .or_else(|| resp.first_text("Status"))
      .unwrap_or_default();
    let cert_pem = resp.first_text("CertificateReturned").unwrap_or_default();
    let chain_pem = resp.first_text("CACertificate").unwrap_or_default();

    Ok(NamecheapCertInfo {
      status,
      cert_pem,
      chain_pem,
    })
  }
}

#[async_trait]
impl CABackend for NamecheapCa {
  fn name(&self) -> &str {
    "namecheap"
  }

  async fn submit(
    &self,
    _domains: &[String],
    csr_pem: &str,
    _preferred_kinds: &[ChallengeKind],
  ) -> Result<Vec<DcvChallenge>> {
    // Namecheap's reissue command: submit the CSR + DNS-DCV election.
    // The response carries either an `<HostName>`/`<Target>` pair (CNAME
    // validation) or a `<TxtName>`/`<TxtValue>` pair depending on the
    // CA tier. Both pairs land inside `<![CDATA[...]]>` blocks so the
    // unescape path matters; see `xml::ApiResponse::first_text`.
    //
    // `preferred_kinds` is ignored: Namecheap reissue only supports
    // DNS-01 over their API. If the operator pairs a Namecheap CA
    // with a webroot DCV solver, the renewer's supports() preflight
    // catches the mismatch and reports it cleanly.
    let resp = self
      .client
      .call(
        "namecheap.ssl.reissue",
        [
          ("CertificateID", self.ssl_id.to_string()),
          ("csr", csr_pem.to_owned()),
          ("DNSDCValidation", "true".to_owned()),
          ("WebServerType", "other".to_owned()),
        ],
      )
      .await?;
    resp.ensure_ok()?;

    let (record_name, record_value) = if let (Some(name), Some(value)) =
      (resp.first_text("TxtName"), resp.first_text("TxtValue"))
    {
      (name, value)
    } else if let (Some(name), Some(target)) =
      (resp.first_text("HostName"), resp.first_text("Target"))
    {
      // CNAME validation surfaces as Name -> Target. We treat it as a
      // TXT record from the trait surface; backends that only accept
      // CNAMEs will reject downstream and we'll widen the trait then.
      (name, target)
    } else {
      // Dump the response at debug level so an operator with
      // `RUST_LOG=debug` can file an actionable bug report without
      // re-curling Namecheap by hand. We landed this diagnostic the
      // hard way: the legacy code returned this exact error string
      // for a different reason (CDATA blocks not unwrapped) and the
      // missing dump cost an avoidable round trip.
      debug!(
        ?resp,
        "namecheap reissue response missing DCV record fields"
      );
      return Err(Error::Ca(
        "namecheap reissue response missing DCV record fields".into(),
      ));
    };

    info!(record = %record_name, "namecheap reissue accepted, dcv pending");
    // Namecheap reissue folds every SAN under one DCV record, so
    // the trait's Vec always has exactly one element here.
    Ok(vec![DcvChallenge::Dns01 {
      record_name,
      record_value,
      ttl: DCV_TTL_SECONDS,
    }])
  }

  async fn await_issuance(&self, _domains: &[String]) -> Result<IssuedCert> {
    let start = std::time::Instant::now();
    loop {
      match self.get_info().await {
        Ok(info) if info.is_issued() => {
          info!("namecheap cert issued");
          return Ok(IssuedCert {
            cert_pem: info.cert_pem,
            chain_pem: info.chain_pem,
          });
        }
        Ok(info) => {
          warn!(status = %info.status, "namecheap cert not ready, polling");
        }
        Err(err) => {
          // Use Display rather than Debug; reqwest's Debug embeds
          // the request URL with `ApiKey=...` query params. Belt-
          // and-braces redaction in case any wrapped layer also
          // surfaces the URL via Display.
          warn!(error = %redact(&err.to_string()), "namecheap getInfo failed, retrying");
        }
      }
      if start.elapsed() > POLL_DEADLINE {
        return Err(Error::Ca("timed out waiting for namecheap issuance".into()));
      }
      tokio::time::sleep(POLL_INTERVAL).await;
    }
  }
}

#[derive(Debug, Clone)]
struct NamecheapCertInfo {
  status: String,
  cert_pem: String,
  chain_pem: String,
}

impl NamecheapCertInfo {
  fn is_issued(&self) -> bool {
    !self.cert_pem.trim().is_empty()
      && (self.status.eq_ignore_ascii_case("active") || self.status.eq_ignore_ascii_case("issued"))
  }
}
