//! Backend traits.
//!
//! Four independent axes:
//!
//! 1. **CA backend**: who signs the cert.
//! 2. **Registrar backend**: where DNS-01 TXT records are published
//!    for domain-control validation.
//! 3. **Install backend**: where the issued cert + chain land so the
//!    system serving the domain can pick them up.
//! 4. **Alert backend**: where lifecycle notifications go (renewal
//!    failures today, more event kinds layer on later).
//!
//! A `CertConfig` picks one of CA + registrar + install; alert
//! backends are daemon-wide and fan out from a single dispatch list.
//! The renewal pipeline composes them generically. Adding support for
//! a new CA, registrar, host, or alert sink is a single trait impl,
//! not a fork of the renewal logic.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

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

  /// Submit a CSR for a new issuance. Returns one or more DCV
  /// challenges the caller must satisfy via the registrar backend
  /// before the CA will sign.
  ///
  /// Single-challenge CAs (Namecheap reissue, anything that folds
  /// SAN authorizations into one record) return a single-element
  /// vec. ACME and friends return one challenge per authorization
  /// (typically one per SAN domain). The caller publishes every
  /// element via `RegistrarBackend::publish_txt` before calling
  /// `await_issuance`, and removes every element afterwards.
  async fn submit(&self, domains: &[String], csr_pem: &str) -> Result<Vec<DcvChallenge>>;

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

  /// Read back the currently-installed leaf cert as PEM if the
  /// backend can introspect what it wrote, or `Ok(None)` if the
  /// backend is write-only or has no cert installed yet.
  ///
  /// Used by the scheduler to compute days-until-expiry against the
  /// configured renewal threshold. Default returns `None` so backends
  /// don't have to opt in until they're ready.
  async fn current_cert_pem(&self, _cert_id: &str) -> Result<Option<String>> {
    Ok(None)
  }
}

/// Lifecycle event the daemon wants to surface to one or more alert
/// sinks. The set of kinds is intentionally small for v0.4; new
/// variants layer on as new event sources land in the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertKind {
  /// A renewal attempt failed. Carries the redacted error string in
  /// [`AlertEvent::message`].
  RenewalFailed,
}

impl AlertKind {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::RenewalFailed => "renewal_failed",
    }
  }
}

/// One alert payload, fanned out to every configured `AlertBackend`.
#[derive(Debug, Clone)]
pub struct AlertEvent {
  /// Cert this event is about.
  pub cert_id: String,
  /// Event classification.
  pub kind: AlertKind,
  /// Human-readable detail. Already redacted by the caller.
  pub message: String,
  /// When the event was generated.
  pub timestamp: DateTime<Utc>,
}

/// Sink for lifecycle notifications. Implementations dispatch one
/// event at a time; the scheduler fans an event out to every
/// configured sink concurrently and swallows individual failures
/// (a flaky alert sink must not break the renewal pipeline).
#[async_trait]
pub trait AlertBackend: Send + Sync {
  /// Stable identifier for this backend (for logs).
  fn name(&self) -> &str;

  /// Deliver `event`. Returning `Err` is logged but does not affect
  /// the renewal pipeline outcome.
  async fn dispatch(&self, event: &AlertEvent) -> Result<()>;
}
