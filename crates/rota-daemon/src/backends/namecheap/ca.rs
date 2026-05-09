//! `namecheap.ssl.reissue` + `namecheap.ssl.getInfo` flow.
//!
//! v0.1 only handles **reissue** within an existing SSL subscription.
//! First-time activation is one-shot and Namecheap requires a long
//! list of admin contact fields that we don't want to model in the
//! config. Operators activate once by hand in Namecheap's UI; rota
//! handles every renewal after that.

use std::sync::atomic::{AtomicU64, Ordering};
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

/// Namecheap CA backend tracks two SSL IDs:
///
/// * `initial_ssl_id` — the ID the operator put in `rota.yaml`. Stays
///   constant; identifies the long-lived SSL subscription line at
///   Namecheap.
/// * `active_ssl_id` — the ID rota currently polls. Each successful
///   `namecheap.ssl.reissue` creates a NEW SSL ID under the same
///   subscription (the original gets `Status="replaced"` and a
///   `ReplacedBy` pointer). `submit()` extracts the new ID from
///   `<SSLReissueResult ID="...">` and stores it here so
///   `await_issuance()` polls the right cert. Falls back to
///   `initial_ssl_id` until the first `submit()` runs.
#[derive(Debug)]
pub struct NamecheapCa {
  client: Arc<NamecheapClient>,
  initial_ssl_id: u64,
  active_ssl_id: AtomicU64,
}

impl NamecheapCa {
  pub fn new(client: Arc<NamecheapClient>, ssl_id: u64) -> Self {
    Self {
      client,
      initial_ssl_id: ssl_id,
      active_ssl_id: AtomicU64::new(ssl_id),
    }
  }

  fn current_ssl_id(&self) -> u64 {
    self.active_ssl_id.load(Ordering::Relaxed)
  }

  async fn get_info(&self) -> Result<NamecheapCertInfo> {
    let resp = self
      .client
      .call(
        "namecheap.ssl.getInfo",
        [
          ("CertificateID", self.current_ssl_id().to_string()),
          ("Returncertificate", "true".to_owned()),
          ("Returntype", "Individual".to_owned()),
        ],
      )
      .await?;
    resp.ensure_ok()?;

    // The actual response carries Status as an attribute on
    // `<SSLGetInfoResult ...>`, not on a separate `<SSLStatus>` element
    // and not as element text. The legacy lookup paths (`SSLStatus`
    // attr + `<Status>` text) are kept as fallbacks for older response
    // shapes but the primary read is now correct.
    let status = resp
      .first_attribute("SSLGetInfoResult", "Status")
      .or_else(|| resp.first_attribute("SSLStatus", "Status"))
      .or_else(|| resp.first_text("Status"))
      .unwrap_or_default();
    let replaced_by = resp
      .first_attribute("SSLGetInfoResult", "ReplacedBy")
      .and_then(|s| s.parse::<u64>().ok());
    // `Returncertificate=true&Returntype=Individual` packs the leaf
    // and chain inside nested `<Certificate>` elements that no naive
    // element-name lookup can disambiguate. The actual PEM armor is
    // unique enough to scan for directly. Document order: the first
    // CERTIFICATE block is the leaf, subsequent ones are the chain
    // (issuer-up); the CSR present in the same response carries the
    // `CERTIFICATE REQUEST` label and is skipped automatically.
    let pem_blocks = resp.pem_blocks("CERTIFICATE");
    let cert_pem = pem_blocks.first().cloned().unwrap_or_default();
    let chain_pem = pem_blocks
      .iter()
      .skip(1)
      .cloned()
      .collect::<Vec<_>>()
      .join("\n");

    Ok(NamecheapCertInfo {
      status,
      cert_pem,
      chain_pem,
      replaced_by,
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
          ("CertificateID", self.initial_ssl_id.to_string()),
          ("csr", csr_pem.to_owned()),
          ("DNSDCValidation", "true".to_owned()),
          ("WebServerType", "other".to_owned()),
        ],
      )
      .await?;
    resp.ensure_ok()?;

    // Capture the new SSL ID Namecheap created for this reissue and
    // promote it to active. Subsequent `get_info` polls land on this
    // new cert rather than on the parent (whose status flips to
    // `replaced` once the reissue is accepted).
    if let Some(new_id) = resp
      .first_attribute("SSLReissueResult", "ID")
      .and_then(|s| s.parse::<u64>().ok())
    {
      let prev = self.active_ssl_id.swap(new_id, Ordering::Relaxed);
      if prev != new_id {
        info!(
          prev_ssl_id = prev,
          new_ssl_id = new_id,
          "namecheap reissue promoted active ssl id"
        );
      }
    }

    let challenge = if let (Some(record_name), Some(record_value)) =
      (resp.first_text("TxtName"), resp.first_text("TxtValue"))
    {
      DcvChallenge::Dns01 {
        record_name,
        record_value,
        ttl: DCV_TTL_SECONDS,
      }
    } else if let (Some(record_name), Some(record_value)) =
      (resp.first_text("HostName"), resp.first_text("Target"))
    {
      // Sectigo CSR-hash and the legacy Comodo CNAME flow both surface
      // as <HostName> -> <Target>. The CA expects a CNAME, NOT a TXT;
      // hostname-validity rules at registrar APIs differ between the
      // two record types (Namecheap rejected `_<MD5>` as TXT name
      // before the trait was widened to carry record type).
      DcvChallenge::DnsCname {
        record_name,
        record_value,
        ttl: DCV_TTL_SECONDS,
      }
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

    info!(record = %challenge.label(), kind = %challenge.kind_str(), "namecheap reissue accepted, dcv pending");
    // Namecheap reissue folds every SAN under one DCV record, so
    // the trait's Vec always has exactly one element here.
    Ok(vec![challenge])
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
        Ok(info) if info.status.eq_ignore_ascii_case("replaced") => {
          // Chase the chain: when an SSL ID has been replaced, the
          // currently-issuing cert lives at `ReplacedBy`. Promote it
          // and skip the sleep so polling can resume against the
          // right ID immediately.
          if let Some(replacement) = info.replaced_by {
            let prev = self.active_ssl_id.swap(replacement, Ordering::Relaxed);
            warn!(
              prev_ssl_id = prev,
              new_ssl_id = replacement,
              "namecheap ssl id replaced, following chain"
            );
            continue;
          }
          warn!("namecheap status=replaced but no ReplacedBy in response, retrying");
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
  /// Set when `<SSLGetInfoResult ReplacedBy="..."/>` is present.
  /// `Status="replaced"` means this cert is no longer the active
  /// one — the operator (or rota's own reissue) created a successor
  /// at this ID.
  replaced_by: Option<u64>,
}

impl NamecheapCertInfo {
  fn is_issued(&self) -> bool {
    !self.cert_pem.trim().is_empty()
      && (self.status.eq_ignore_ascii_case("active") || self.status.eq_ignore_ascii_case("issued"))
  }
}
