//! Backend traits — the load-bearing abstractions.
//!
//! Three independent axes:
//!
//! 1. **CA backend** — who signs the cert.
//! 2. **Registrar backend** — where DNS-01 TXT records are published
//!    for domain-control validation.
//! 3. **Install backend** — where the issued cert + chain land so the
//!    system serving the domain can pick them up.
//!
//! A `CertConfig` picks one of each; the renewal pipeline composes
//! them generically. Adding support for a new CA, registrar, or host
//! is a single trait impl, not a fork of the renewal logic.

use async_trait::async_trait;

use crate::Result;

/// Material returned from a CA after successful issuance.
#[derive(Debug, Clone)]
pub struct IssuedCert {
  /// PEM-encoded leaf certificate.
  pub cert_pem: String,
  /// PEM-encoded intermediate chain (issuer-up).
  pub chain_pem: String,
}

/// A DNS-01 challenge the CA wants validated.
#[derive(Debug, Clone)]
pub struct DcvChallenge {
  /// FQDN at which the TXT record must be published
  /// (e.g. `_acme-challenge.example.com` or whatever the CA dictates).
  pub record_name: String,
  /// Value the TXT record must hold.
  pub record_value: String,
  /// Time-to-live for the TXT record in seconds.
  pub ttl: u32,
}

/// Issues certificates from a Certificate Authority.
#[async_trait]
pub trait CABackend: Send + Sync {
  /// Stable identifier for this backend (for logs + audit).
  fn name(&self) -> &str;

  /// Submit a CSR for a new issuance. Returns the DCV challenge the
  /// caller needs to satisfy via the registrar backend before the CA
  /// will sign.
  async fn submit(&self, domains: &[String], csr_pem: &str) -> Result<DcvChallenge>;

  /// Poll the CA until the cert is signed or a timeout/error occurs.
  /// Called after the registrar has published the DCV TXT.
  async fn await_issuance(&self, domains: &[String]) -> Result<IssuedCert>;
}

/// Manages DNS records at a registrar for DNS-01 DCV.
#[async_trait]
pub trait RegistrarBackend: Send + Sync {
  /// Stable identifier for this backend.
  fn name(&self) -> &str;

  /// Publish a TXT record. Idempotent: if a record with the same name
  /// + value already exists, treat as success.
  async fn publish_txt(&self, challenge: &DcvChallenge) -> Result<()>;

  /// Remove a previously-published TXT record. Idempotent: if no such
  /// record exists, treat as success.
  async fn remove_txt(&self, challenge: &DcvChallenge) -> Result<()>;
}

/// Places an issued cert where the system serving the domain can find
/// it. Implementations may also trigger a reload of the consuming
/// service (nginx, HAProxy, DSM's nginx, etc.).
#[async_trait]
pub trait InstallBackend: Send + Sync {
  /// Stable identifier for this backend.
  fn name(&self) -> &str;

  /// Install the issued cert + chain. The private key is read from
  /// the configured `key_path` by the caller and passed in directly
  /// so backends do not need filesystem access to it.
  async fn install(
    &self,
    cert: &IssuedCert,
    private_key_pem: &str,
    domains: &[String],
  ) -> Result<()>;
}
