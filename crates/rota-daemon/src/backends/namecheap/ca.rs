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
use md5::{Digest, Md5};
use rota_core::backend::{CABackend, ChallengeKind, DcvChallenge, IssuedCert};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use sha2::Sha256;
use tracing::{debug, info, warn};

use super::client::NamecheapClient;

const POLL_INTERVAL: Duration = Duration::from_secs(30);
const POLL_DEADLINE: Duration = Duration::from_secs(60 * 30); // 30 min
const DCV_TTL_SECONDS: u32 = 300;
/// Sectigo's deployed DCV target zone for the CSR-hash CNAME flow.
/// Sectigo's marketing pages occasionally cite `sectigo.com`, but the
/// actual validation infrastructure (and every reseller KB plus the
/// Namecheap response examples) uses `comodoca.com`.
const SECTIGO_DCV_TARGET_ZONE: &str = "comodoca.com";

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
    domains: &[String],
    csr_pem: &str,
    _preferred_kinds: &[ChallengeKind],
  ) -> Result<Vec<DcvChallenge>> {
    // Namecheap's reissue command: submit the CSR + DNS-DCV election.
    // The response carries one of three shapes:
    // 1. `<TxtName>`/`<TxtValue>`: TXT-record DCV (legacy Sectigo
    //    flow on some products).
    // 2. `<HostName>`/`<Target>`: CNAME-record DCV with the values
    //    returned inline (older Comodo flow).
    // 3. `<ApproverEmail>CNAMECSRHASH</ApproverEmail>` and NO record
    //    fields: modern Sectigo flow where the CNAME is computed
    //    locally from the CSR per Sectigo DCV spec v1.09. Most
    //    Namecheap-issued PositiveSSL certs use this in 2026+.
    //
    // We try the explicit-record shapes first because they're cheap
    // string lookups, then fall through to the CSR-hash compute when
    // the response indicates `CNAMECSRHASH`.
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
    } else if resp
      .first_text("ApproverEmail")
      .map(|v| v.eq_ignore_ascii_case("CNAMECSRHASH"))
      .unwrap_or(false)
    {
      let domain = domains.first().ok_or_else(|| {
        Error::Ca("namecheap reissue: at least one domain is required for CSR-hash DCV".into())
      })?;
      let challenge = compute_csrhash_dcv(csr_pem, domain)?;
      info!(domain = %domain, "namecheap reissue accepted, csr-hash dcv computed");
      return Ok(vec![challenge]);
    } else {
      // None of the three known response shapes matched. Dump the
      // response at debug level so an operator with `RUST_LOG=debug`
      // can file an actionable bug report without re-curling
      // Namecheap by hand.
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

/// Compute the Sectigo CNAME-CSR-Hash DCV record from a PEM-encoded
/// CSR per Sectigo's "Domain Control Validation" spec v1.09.
///
/// The algorithm is purely deterministic from the DER-encoded CSR
/// bytes, so no network round-trip is needed once rota has the CSR
/// it submitted to Namecheap. The result plugs into the existing
/// `DcvChallenge::Dns01` trait surface; a `DcvBackend` (Namecheap or
/// Cloudflare) publishes the CNAME and Sectigo's resolver picks it
/// up the same way it does for the explicit-response flows.
///
/// Format produced:
/// * Host: `_<MD5_HEX_UPPERCASE>.<domain>`
/// * Target: `<SHA256_HEX_FIRST32>.<SHA256_HEX_LAST32>.comodoca.com`
///
/// The SHA256 hex (64 chars) is split with one `.` after the 32nd
/// char so neither label exceeds DNS's 63-octet limit. The MD5 hex
/// stays uppercase to match the published spec.
fn compute_csrhash_dcv(csr_pem: &str, domain: &str) -> Result<DcvChallenge> {
  let der = pem::parse(csr_pem)
    .map_err(|e| Error::Ca(format!("namecheap CSR PEM parse: {e}")))?
    .into_contents();
  let md5_hex_upper = hex::encode_upper(Md5::digest(&der));
  let sha256_hex = hex::encode(Sha256::digest(&der));
  let (sha256_first, sha256_second) = sha256_hex.split_at(32);
  Ok(DcvChallenge::Dns01 {
    record_name: format!("_{md5_hex_upper}.{domain}"),
    record_value: format!("{sha256_first}.{sha256_second}.{SECTIGO_DCV_TARGET_ZONE}"),
    ttl: DCV_TTL_SECONDS,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn fixture_csr_pem() -> String {
    // Random key per call: we can't pin exact hash values, but the
    // OUTPUT SHAPE (label lengths, hex case, zone suffix) is what
    // Sectigo's spec pins down, so structural assertions are enough.
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
    let csr = params.serialize_request(&key).unwrap();
    csr.pem().unwrap()
  }

  #[test]
  fn cnamecsrhash_record_has_expected_shape() {
    let csr_pem = fixture_csr_pem();
    let challenge = compute_csrhash_dcv(&csr_pem, "example.com").unwrap();
    let DcvChallenge::Dns01 {
      record_name,
      record_value,
      ttl,
    } = challenge
    else {
      panic!("expected Dns01");
    };

    assert!(
      record_name.starts_with('_'),
      "host must start with `_`: {record_name}"
    );
    assert!(
      record_name.ends_with(".example.com"),
      "host must end with the domain: {record_name}"
    );
    let md5_label = record_name
      .strip_prefix('_')
      .unwrap()
      .strip_suffix(".example.com")
      .unwrap();
    assert_eq!(
      md5_label.len(),
      32,
      "MD5 hex should be 32 chars: {md5_label}"
    );
    assert!(
      md5_label
        .chars()
        .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)),
      "MD5 hex must be uppercase: {md5_label}"
    );

    assert!(
      record_value.ends_with(".comodoca.com"),
      "target zone must be comodoca.com: {record_value}"
    );
    let sha_part = record_value.strip_suffix(".comodoca.com").unwrap();
    let labels: Vec<&str> = sha_part.split('.').collect();
    assert_eq!(
      labels.len(),
      2,
      "SHA256 must split across two labels: {record_value}"
    );
    assert_eq!(labels[0].len(), 32);
    assert_eq!(labels[1].len(), 32);
    assert!(
      labels[0]
        .chars()
        .chain(labels[1].chars())
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
      "SHA256 hex must be lowercase: {record_value}"
    );

    assert_eq!(ttl, DCV_TTL_SECONDS);
  }

  #[test]
  fn cnamecsrhash_uses_supplied_domain_not_csr_cn() {
    let csr_pem = fixture_csr_pem();
    let challenge = compute_csrhash_dcv(&csr_pem, "different.example.org").unwrap();
    let DcvChallenge::Dns01 { record_name, .. } = challenge else {
      panic!("expected Dns01");
    };
    assert!(
      record_name.ends_with(".different.example.org"),
      "compute_csrhash_dcv treats `domain` as authoritative: {record_name}"
    );
  }

  #[test]
  fn cnamecsrhash_is_deterministic_for_same_csr() {
    let csr_pem = fixture_csr_pem();
    let a = compute_csrhash_dcv(&csr_pem, "example.com").unwrap();
    let b = compute_csrhash_dcv(&csr_pem, "example.com").unwrap();
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
  }

  #[test]
  fn cnamecsrhash_rejects_invalid_pem() {
    let err = compute_csrhash_dcv("not a real PEM", "example.com").unwrap_err();
    assert!(
      err.to_string().contains("CSR PEM parse"),
      "error should name the parse failure: {err}"
    );
  }
}
