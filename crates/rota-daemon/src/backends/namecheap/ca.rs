//! `namecheap.ssl.reissue` + `namecheap.ssl.getInfo` flow.
//!
//! v0.1 only handles **reissue** within an existing SSL subscription.
//! First-time activation is one-shot and Namecheap requires a long
//! list of admin contact fields that we don't want to model in the
//! config. Operators activate once by hand in Namecheap's UI; rota
//! handles every renewal after that.

use std::collections::HashSet;
use std::future::Future;
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
/// Most links followed from the configured SSL ID to the current
/// certificate. Each renewal adds one link, so a chain this long takes
/// decades of renewals; reaching it means the chain loops.
const MAX_CHAIN_HOPS: usize = 32;

/// Namecheap CA backend tracks two SSL IDs:
///
/// * `initial_ssl_id` — the ID the operator put in `rota.yaml`. Stays
///   constant; identifies the long-lived SSL subscription line at
///   Namecheap. It is where every renewal starts looking, not what it
///   reissues: after the first reissue it is `replaced`, and Namecheap
///   refuses to reissue a replaced certificate (`4011331: Status is
///   InValid`). `submit()` follows the `ReplacedBy` chain from here to
///   the current certificate and reissues that one.
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
    self.get_info_for(self.current_ssl_id(), true).await
  }

  /// `namecheap.ssl.getInfo` for one SSL ID. `with_cert` asks for the
  /// PEMs as well; the chain walk needs only the status.
  async fn get_info_for(&self, ssl_id: u64, with_cert: bool) -> Result<NamecheapCertInfo> {
    let mut params = vec![("CertificateID", ssl_id.to_string())];
    if with_cert {
      params.push(("Returncertificate", "true".to_owned()));
      params.push(("Returntype", "Individual".to_owned()));
    }
    let resp = self.client.call("namecheap.ssl.getInfo", params).await?;
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

  /// The SSL ID a reissue must target: the end of the `ReplacedBy`
  /// chain that starts at the configured ID, with its status.
  async fn reissue_target(&self) -> Result<(u64, String)> {
    follow_replacements(self.initial_ssl_id, |id| async move {
      let info = self.get_info_for(id, false).await?;
      Ok((info.status, info.replaced_by))
    })
    .await
  }
}

/// Walk Namecheap's `ReplacedBy` chain from `start` to the first SSL ID
/// that is not `replaced`, and return it with its status. `lookup`
/// gives an ID's status and successor. A replaced ID with no successor,
/// a loop, or a chain longer than [`MAX_CHAIN_HOPS`] is an error.
async fn follow_replacements<F, Fut>(start: u64, mut lookup: F) -> Result<(u64, String)>
where
  F: FnMut(u64) -> Fut,
  Fut: Future<Output = Result<(String, Option<u64>)>>,
{
  let mut id = start;
  let mut seen = HashSet::new();
  for _ in 0..=MAX_CHAIN_HOPS {
    if !seen.insert(id) {
      return Err(Error::Ca(format!(
        "namecheap ReplacedBy chain from ssl id {start} loops back to {id}"
      )));
    }
    let (status, replaced_by) = lookup(id).await?;
    if !status.eq_ignore_ascii_case("replaced") {
      return Ok((id, status));
    }
    match replaced_by {
      Some(next) => id = next,
      None => {
        return Err(Error::Ca(format!(
          "namecheap ssl id {id} is replaced but names no successor"
        )))
      }
    }
  }
  Err(Error::Ca(format!(
    "namecheap ReplacedBy chain from ssl id {start} is longer than {MAX_CHAIN_HOPS} links"
  )))
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
    let (target, status) = self.reissue_target().await?;
    if target != self.initial_ssl_id {
      info!(
        configured_ssl_id = self.initial_ssl_id,
        current_ssl_id = target,
        %status,
        "namecheap reissue targets the current certificate in the chain"
      );
    }
    self.active_ssl_id.store(target, Ordering::Relaxed);
    let resp = self
      .client
      .call(
        "namecheap.ssl.reissue",
        [
          ("CertificateID", target.to_string()),
          ("csr", csr_pem.to_owned()),
          ("DNSDCValidation", "true".to_owned()),
          ("WebServerType", "other".to_owned()),
        ],
      )
      .await?;
    resp.ensure_ok().map_err(|err| match err {
      Error::Ca(msg) => Error::Ca(format!(
        "reissue of ssl id {target} (status {status}): {msg}"
      )),
      other => other,
    })?;

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

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use super::*;

  /// A fake Namecheap: each SSL ID's status and successor.
  fn chain(links: &[(u64, &str, Option<u64>)]) -> HashMap<u64, (String, Option<u64>)> {
    links
      .iter()
      .map(|&(id, status, next)| (id, (status.to_owned(), next)))
      .collect()
  }

  async fn walk(start: u64, ids: &HashMap<u64, (String, Option<u64>)>) -> Result<(u64, String)> {
    follow_replacements(start, |id| {
      let found = ids.get(&id).cloned();
      async move { found.ok_or_else(|| Error::Ca(format!("no ssl id {id}"))) }
    })
    .await
  }

  #[tokio::test]
  async fn an_active_configured_id_is_its_own_target() {
    let ids = chain(&[(100, "active", None)]);
    let (id, status) = walk(100, &ids).await.expect("an active id resolves");
    assert_eq!((id, status.as_str()), (100, "active"));
  }

  #[tokio::test]
  async fn a_replaced_id_resolves_to_the_end_of_its_chain() {
    // The configured id was reissued twice: rota must reissue the latest.
    let ids = chain(&[
      (100, "replaced", Some(200)),
      (200, "Replaced", Some(300)),
      (300, "active", None),
    ]);
    let (id, status) = walk(100, &ids).await.expect("the chain resolves");
    assert_eq!((id, status.as_str()), (300, "active"));
  }

  #[tokio::test]
  async fn the_end_of_the_chain_is_returned_whatever_its_status() {
    let ids = chain(&[(100, "replaced", Some(200)), (200, "purchased", None)]);
    let (id, status) = walk(100, &ids).await.expect("the chain resolves");
    assert_eq!((id, status.as_str()), (200, "purchased"));
  }

  #[tokio::test]
  async fn a_replaced_id_without_a_successor_is_an_error() {
    let ids = chain(&[(100, "replaced", None)]);
    let err = walk(100, &ids).await.expect_err("a dead end is refused");
    assert!(err.to_string().contains("names no successor"), "{err}");
  }

  #[tokio::test]
  async fn a_loop_is_an_error() {
    let ids = chain(&[(100, "replaced", Some(200)), (200, "replaced", Some(100))]);
    let err = walk(100, &ids).await.expect_err("a loop is refused");
    assert!(err.to_string().contains("loops back"), "{err}");
  }

  #[tokio::test]
  async fn a_chain_longer_than_the_limit_is_an_error() {
    let links: Vec<(u64, &str, Option<u64>)> = (0..=(MAX_CHAIN_HOPS as u64 + 1))
      .map(|i| (i, "replaced", Some(i + 1)))
      .collect();
    let ids = chain(&links);
    let err = walk(0, &ids)
      .await
      .expect_err("an endless chain is refused");
    assert!(err.to_string().contains("longer than"), "{err}");
  }

  #[tokio::test]
  async fn a_lookup_failure_stops_the_walk() {
    let ids = chain(&[(100, "replaced", Some(200))]);
    let err = walk(100, &ids).await.expect_err("a missing id is an error");
    assert!(err.to_string().contains("no ssl id 200"), "{err}");
  }
}
