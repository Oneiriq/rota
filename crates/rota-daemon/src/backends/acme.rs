//! ACME (RFC 8555) CA backend.
//!
//! Speaks any ACME directory: Let's Encrypt, ZeroSSL, BuyPass, etc.
//! Uses the `instant-acme` crate for the JWS-signed wire format and
//! state-machine handling; rota wraps it with persistent account
//! credentials and the in-flight-order map that the trait's
//! split-submit / split-await flow needs.
//!
//! Why state in the impl: rota's `CABackend::submit` returns DCV
//! challenges to publish, and `await_issuance` is a separate call.
//! ACME's `Order` has to thread between the two, so `submit` stashes
//! the order (keyed by sorted domain list) and `await_issuance`
//! pops it back out. The mutex is touched once per renewal and the
//! map carries at most one entry per cert; contention is non-issue.
//!
//! Why we don't use `instant_acme::Order::finalize`: rota manages
//! its own persistent ECDSA key per cert (operators rely on key
//! continuity for cert pinning). We use `finalize_csr(csr_der)` so
//! the renewer's key stays canonical; instant-acme's library-managed
//! key path is for first-class consumers, not for operators with
//! their own keys.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use instant_acme::{
  Account, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier, NewAccount, NewOrder,
  Order, OrderStatus, RetryPolicy,
};
use rota_core::backend::{CABackend, DcvChallenge, IssuedCert};
use rota_core::config::{AcmeAccount, EabConfig};
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const DCV_TTL_SECONDS: u32 = 60;
const POLL_DEADLINE: Duration = Duration::from_secs(60 * 30);

#[derive(Clone)]
pub struct AcmeCa {
  account: Arc<Account>,
  in_flight: Arc<Mutex<HashMap<DomainKey, OrderInFlight>>>,
}

/// Domain set keyed for the in-flight map. Sorted so callers can
/// pass domains in any order without breaking the lookup.
type DomainKey = Vec<String>;

struct OrderInFlight {
  order: Order,
  /// DER-encoded CSR captured during `submit`. The renewer hands us
  /// PEM; we decode once and stash so `finalize_csr` doesn't have
  /// to repeat the parse.
  csr_der: Vec<u8>,
}

impl std::fmt::Debug for AcmeCa {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("AcmeCa").finish_non_exhaustive()
  }
}

impl AcmeCa {
  /// Open or create the ACME account at the configured directory.
  ///
  /// First call: registers a fresh account, writes credentials to
  /// `account_credentials_file`. Subsequent calls: reads the file
  /// and rehydrates the existing account.
  pub async fn from_spec(spec: &AcmeAccount) -> Result<Self> {
    let account = match load_account(&spec.account_credentials_file).await {
      Some(creds) => Account::builder()
        .map_err(|e| Error::Ca(format!("acme account builder: {e}")))?
        .from_credentials(creds)
        .await
        .map_err(|e| Error::Ca(format!("acme rehydrate: {}", redact(&e.to_string()))))?,
      None => create_account(spec).await?,
    };
    Ok(Self {
      account: Arc::new(account),
      in_flight: Arc::new(Mutex::new(HashMap::new())),
    })
  }
}

async fn load_account(path: &Path) -> Option<AccountCredentials> {
  let raw = tokio::fs::read_to_string(path).await.ok()?;
  serde_json::from_str(&raw).ok()
}

async fn create_account(spec: &AcmeAccount) -> Result<Account> {
  let mut new = NewAccount {
    contact: &[],
    terms_of_service_agreed: true,
    only_return_existing: false,
  };
  let contact = spec
    .contact_email
    .as_ref()
    .map(|e| format!("mailto:{e}"))
    .into_iter()
    .collect::<Vec<_>>();
  let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
  new.contact = &contact_refs;

  let eab = match &spec.external_account_binding {
    Some(eab) => Some(load_eab(eab).await?),
    None => None,
  };

  let builder = Account::builder().map_err(|e| Error::Ca(format!("acme account builder: {e}")))?;
  let (account, creds) = builder
    .create(&new, spec.directory_url.clone(), eab.as_ref())
    .await
    .map_err(|e| Error::Ca(format!("acme account create: {}", redact(&e.to_string()))))?;

  persist_account(&spec.account_credentials_file, &creds).await?;
  info!(
    directory = %spec.directory_url,
    path = %spec.account_credentials_file.display(),
    "acme account registered + persisted"
  );
  Ok(account)
}

async fn load_eab(eab: &EabConfig) -> Result<ExternalAccountKey> {
  let hmac = tokio::fs::read_to_string(&eab.hmac_key_file)
    .await
    .map_err(|e| {
      Error::Ca(format!(
        "read eab hmac {}: {e}",
        eab.hmac_key_file.display()
      ))
    })?
    .trim()
    .to_owned();
  Ok(ExternalAccountKey::new(eab.kid.clone(), hmac.as_bytes()))
}

async fn persist_account(path: &Path, creds: &AccountCredentials) -> Result<()> {
  if let Some(parent) = path.parent() {
    tokio::fs::create_dir_all(parent)
      .await
      .map_err(|e| Error::Ca(format!("acme creds dir {}: {e}", parent.display())))?;
  }
  let json =
    serde_json::to_vec(creds).map_err(|e| Error::Ca(format!("serialise acme creds: {e}")))?;
  let mut f = tokio::fs::OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .mode(0o600)
    .open(path)
    .await
    .map_err(|e| Error::Ca(format!("open acme creds {}: {e}", path.display())))?;
  use tokio::io::AsyncWriteExt;
  f.write_all(&json)
    .await
    .map_err(|e| Error::Ca(format!("write acme creds: {e}")))?;
  f.sync_all()
    .await
    .map_err(|e| Error::Ca(format!("fsync acme creds: {e}")))?;
  Ok(())
}

fn key_for(domains: &[String]) -> DomainKey {
  let mut k = domains.to_vec();
  k.sort();
  k
}

fn pem_to_der(csr_pem: &str) -> Result<Vec<u8>> {
  let parsed = pem::parse(csr_pem).map_err(|e| Error::Ca(format!("parse csr pem: {e}")))?;
  Ok(parsed.into_contents())
}

#[async_trait]
impl CABackend for AcmeCa {
  fn name(&self) -> &str {
    "acme"
  }

  async fn submit(&self, domains: &[String], csr_pem: &str) -> Result<Vec<DcvChallenge>> {
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = self
      .account
      .new_order(&NewOrder::new(&identifiers))
      .await
      .map_err(|e| Error::Ca(format!("acme new_order: {}", redact(&e.to_string()))))?;

    let mut challenges = Vec::with_capacity(domains.len());
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
      let mut authz =
        result.map_err(|e| Error::Ca(format!("acme authorization: {}", redact(&e.to_string()))))?;
      let domain = match authz.identifier().identifier {
        Identifier::Dns(d) => d.clone(),
        other => {
          return Err(Error::Ca(format!(
            "acme returned non-DNS identifier: {other:?}"
          )));
        }
      };
      let challenge = authz
        .challenge(ChallengeType::Dns01)
        .ok_or_else(|| Error::Ca(format!("no dns-01 challenge for {domain}")))?;
      let dns_value = challenge.key_authorization().dns_value();
      challenges.push(DcvChallenge::Dns01 {
        record_name: format!("_acme-challenge.{domain}"),
        record_value: dns_value,
        ttl: DCV_TTL_SECONDS,
      });
    }
    let _ = authorizations;

    let csr_der = pem_to_der(csr_pem)?;
    self
      .in_flight
      .lock()
      .await
      .insert(key_for(domains), OrderInFlight { order, csr_der });

    info!(
      domains = ?domains,
      challenge_count = challenges.len(),
      "acme order placed; dcv records pending"
    );
    Ok(challenges)
  }

  async fn await_issuance(&self, domains: &[String]) -> Result<IssuedCert> {
    let key = key_for(domains);
    let mut entry = {
      let mut map = self.in_flight.lock().await;
      map.remove(&key).ok_or_else(|| {
        Error::Ca(format!(
          "acme await_issuance with no submitted order for {domains:?}"
        ))
      })?
    };

    // Tell the CA every dns-01 challenge is ready. Walk the
    // authorizations again because we let them drop after submit
    // (the iterator borrows the order mutably).
    let mut authorizations = entry.order.authorizations();
    while let Some(result) = authorizations.next().await {
      let mut authz =
        result.map_err(|e| Error::Ca(format!("acme reauthorize: {}", redact(&e.to_string()))))?;
      let mut challenge = authz
        .challenge(ChallengeType::Dns01)
        .ok_or_else(|| Error::Ca("dns-01 challenge vanished".into()))?;
      challenge
        .set_ready()
        .await
        .map_err(|e| Error::Ca(format!("acme set_ready: {}", redact(&e.to_string()))))?;
    }
    let _ = authorizations;

    let policy = RetryPolicy::default().timeout(POLL_DEADLINE);
    let status = entry
      .order
      .poll_ready(&policy)
      .await
      .map_err(|e| Error::Ca(format!("acme poll_ready: {}", redact(&e.to_string()))))?;
    if !matches!(status, OrderStatus::Ready) {
      return Err(Error::Ca(format!(
        "acme order not ready after dcv: status={status:?}"
      )));
    }

    entry
      .order
      .finalize_csr(&entry.csr_der)
      .await
      .map_err(|e| Error::Ca(format!("acme finalize_csr: {}", redact(&e.to_string()))))?;

    let cert_pem = entry
      .order
      .poll_certificate(&policy)
      .await
      .map_err(|e| Error::Ca(format!("acme poll_certificate: {}", redact(&e.to_string()))))?;

    let (leaf, chain) = split_chain(&cert_pem);
    debug!(
      leaf_bytes = leaf.len(),
      chain_bytes = chain.len(),
      "acme cert downloaded"
    );
    if leaf.is_empty() {
      warn!("acme certificate response had no leaf cert");
    }
    Ok(IssuedCert {
      cert_pem: leaf,
      chain_pem: chain,
    })
  }
}

/// ACME's `poll_certificate` returns one PEM bundle with the leaf
/// followed by the issuer chain. rota's `IssuedCert` separates them
/// so install backends can decide whether to write `chain.crt` or
/// `fullchain.crt`. Splits at the second `BEGIN CERTIFICATE`
/// boundary; everything before is the leaf, everything from there
/// on is the chain.
fn split_chain(bundle: &str) -> (String, String) {
  const MARKER: &str = "-----BEGIN CERTIFICATE-----";
  let mut indices = bundle
    .match_indices(MARKER)
    .map(|(i, _)| i)
    .collect::<Vec<_>>();
  if indices.len() <= 1 {
    return (bundle.to_owned(), String::new());
  }
  let split = indices.remove(1);
  let leaf = bundle[..split].trim_end_matches('\n').to_owned() + "\n";
  let chain = bundle[split..].to_owned();
  (leaf, chain)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn fake_pem(label: &str) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n")
  }

  #[test]
  fn split_chain_separates_leaf_from_intermediates() {
    let bundle = format!("{}{}", fake_pem("LEAF"), fake_pem("ISSUER"));
    let (leaf, chain) = split_chain(&bundle);
    assert!(leaf.contains("LEAF"));
    assert!(!leaf.contains("ISSUER"));
    assert!(chain.contains("ISSUER"));
    assert!(!chain.contains("LEAF"));
  }

  #[test]
  fn split_chain_handles_three_certs() {
    let bundle = format!(
      "{}{}{}",
      fake_pem("LEAF"),
      fake_pem("MID"),
      fake_pem("ROOT")
    );
    let (leaf, chain) = split_chain(&bundle);
    assert!(leaf.contains("LEAF"));
    assert!(chain.contains("MID"));
    assert!(chain.contains("ROOT"));
  }

  #[test]
  fn split_chain_with_only_leaf_returns_empty_chain() {
    let bundle = fake_pem("ONLY");
    let (leaf, chain) = split_chain(&bundle);
    assert!(leaf.contains("ONLY"));
    assert!(chain.is_empty());
  }

  #[test]
  fn key_for_normalises_order() {
    let a = key_for(&["b.example.com".to_owned(), "a.example.com".to_owned()]);
    let b = key_for(&["a.example.com".to_owned(), "b.example.com".to_owned()]);
    assert_eq!(a, b);
  }

  #[test]
  fn pem_to_der_roundtrips_a_real_csr() {
    let pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIICVDCCATwCAQAwDzENMAsGA1UEAwwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAKj7zQU8u/n0vZ2oJfJ7xiCS8vK19yRnk6rL9X3wOUzClYkW\nGi2bE0e7AGN7w+tjHTcLcBFSRmUH2+YEsj57wB+EaFtswQrf9MihFp94JFtoaE5d\nyQUkOMG1tA2HOlLm2kzsfHjqRIBPTkFwMzLTBbT8IRRWb/xTCC7wH0GTtHkk/6BL\nRvgzCcBSOl5gn8/aqBR/cwSh+pQjj3l4G2y5HQUdWX0jBvXZj8FbLTL8a8m+oRwI\nP9SZ6rZkJ1vS1xCt0EWxdM4l1cZZCRH7/Tu59MKpkSRRkRYHSUM4Y5K1G8a0JZmd\nBFPdJ3DSvLn6V4+NJYP0r7rRDsmM/o1jOAUCAwEAAaAAMA0GCSqGSIb3DQEBCwUA\nA4IBAQAyN9X64yxEK04r2JD3X1DPVF4XJiYVDPtDEWnWKfNS2Yw7q1mD/MZWS6qK\nnVnPYxZ1FbSvCPkjTJp/6S1H0eRH0+T1AJlTo4nKPXg8YA8w+LYfLmQqmFPBAaEf\ndIJj6Dq+qVRMUhVdCu6/Po7Zdw5JJN8Em/U1IZl1sXTmJ65xxGdYi9dZbSWJaqaw\n5d3JTr8yWJrSBxPGJ8jvByJ0iIuSY5FGSJHkPAYhdARtj3ZD1lGxZcWFqsxVz/A0\n2nB+zEEhfP6X9vBe8Y2uy0tGkqLi2Lmc9p1wJtL6f9zWsVj0XSc3M4cDZb6xkhKi\nKjbeQq6F+iE4LbKzZL8FcaKt+Aei\n-----END CERTIFICATE REQUEST-----\n";
    // Decoder doesn't validate the contents; it just round-trips
    // the base64. We just want to confirm the helper handles the
    // PEM framing without panicking.
    let result = pem_to_der(pem);
    assert!(result.is_ok(), "pem_to_der should succeed: {result:?}");
  }
}
