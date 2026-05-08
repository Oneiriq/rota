//! Backend traits.
//!
//! Four independent axes:
//!
//! 1. **CA backend**: who signs the cert.
//! 2. **DCV backend**: how domain-control validation gets satisfied.
//!    DNS-01 backends publish TXT records at the registrar; HTTP-01
//!    backends drop a token under `/.well-known/acme-challenge/` for
//!    a webserver to serve.
//! 3. **Install backend**: where the issued cert + chain land so the
//!    system serving the domain can pick them up.
//! 4. **Alert backend**: where lifecycle notifications go (renewal
//!    failures today, more event kinds layer on later).
//!
//! A `CertConfig` picks one of CA + DCV + install; alert backends
//! are daemon-wide and fan out from a single dispatch list. The
//! renewal pipeline composes them generically. Adding support for a
//! new CA, DCV strategy, host, or alert sink is a single trait impl,
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

/// Discriminant for a [`DcvChallenge`]: the bare kind without a
/// payload. Lets backends advertise which kinds they support and
/// lets the renewer hint at the CA's challenge-type selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeKind {
  Dns01,
  Http01,
}

impl ChallengeKind {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Dns01 => "dns-01",
      Self::Http01 => "http-01",
    }
  }
}

/// A domain-control-validation challenge the CA wants satisfied.
/// Tagged enum so the renewer can dispatch each challenge to a DCV
/// backend that supports its kind.
#[derive(Debug, Clone)]
pub enum DcvChallenge {
  /// DNS-01: publish a TXT record at `record_name` with
  /// `record_value`. The CA polls DNS and signs once it sees the
  /// record. Solver is typically the operator's registrar / DNS
  /// provider.
  Dns01 {
    /// FQDN at which the TXT record must be published
    /// (e.g. `_acme-challenge.example.com`).
    record_name: String,
    /// Value the TXT record must hold.
    record_value: String,
    /// Time-to-live for the TXT record in seconds.
    ttl: u32,
  },
  /// HTTP-01: serve `key_authorization` at
  /// `http://<domain>/.well-known/acme-challenge/<token>` over
  /// plain HTTP on port 80. The CA fetches the URL and signs once
  /// it reads the expected body. Solver is typically a webroot
  /// drop or a dedicated rotad listener.
  Http01 {
    /// Domain the CA will GET against (no scheme, no path).
    domain: String,
    /// Token to expose at the well-known URL.
    token: String,
    /// Body the well-known URL must return: per RFC 8555 this is
    /// `<token>.<base64url(thumbprint(account-key))>`.
    key_authorization: String,
  },
}

impl DcvChallenge {
  /// Discriminant of this challenge, payload-stripped. Useful for
  /// matching against `DcvBackend::supported_kinds()` without moving
  /// the enum around.
  pub fn kind(&self) -> ChallengeKind {
    match self {
      Self::Dns01 { .. } => ChallengeKind::Dns01,
      Self::Http01 { .. } => ChallengeKind::Http01,
    }
  }

  /// Stable short identifier for the challenge kind, suitable for
  /// audit log fields and error messages.
  pub fn kind_str(&self) -> &'static str {
    self.kind().as_str()
  }

  /// Short label identifying *what* this challenge is for, for
  /// audit log details. DNS-01 returns the record name; HTTP-01
  /// returns the domain.
  pub fn label(&self) -> String {
    match self {
      Self::Dns01 { record_name, .. } => record_name.clone(),
      Self::Http01 { domain, .. } => format!("{domain} (http-01)"),
    }
  }
}

/// Issues certificates from a Certificate Authority.
#[async_trait]
pub trait CABackend: Send + Sync {
  /// Stable identifier for this backend (for logs + audit).
  fn name(&self) -> &str;

  /// Submit a CSR for a new issuance. Returns one or more DCV
  /// challenges the caller must satisfy via the DCV backend before
  /// the CA will sign.
  ///
  /// `preferred_kinds` is a hint from the configured DCV backend
  /// about which challenge types it can satisfy, in preference
  /// order. CAs that offer a choice (ACME) walk the list and pick
  /// the first kind on offer; CAs that only support one kind
  /// (Namecheap reissue) ignore the hint and return whatever they
  /// natively produce. The renewer's `supports()` preflight catches
  /// any actual mismatch before publish runs.
  ///
  /// Single-challenge CAs (Namecheap reissue, anything that folds
  /// SAN authorizations into one record) return a single-element
  /// vec. ACME and friends return one challenge per authorization
  /// (typically one per SAN domain). The caller publishes every
  /// element via `DcvBackend::publish` before calling
  /// `await_issuance`, and removes every element afterwards.
  async fn submit(
    &self,
    domains: &[String],
    csr_pem: &str,
    preferred_kinds: &[ChallengeKind],
  ) -> Result<Vec<DcvChallenge>>;

  /// Poll the CA until the cert is signed or a timeout/error occurs.
  /// Called after the DCV backend has published every challenge.
  async fn await_issuance(&self, domains: &[String]) -> Result<IssuedCert>;
}

/// Solver for domain-control-validation challenges. The renewer
/// dispatches each challenge to a DCV backend that supports its
/// kind. DNS-01 solvers manage TXT records at a registrar; HTTP-01
/// solvers expose a token at a well-known URL.
#[async_trait]
pub trait DcvBackend: Send + Sync {
  /// Stable identifier for this backend.
  fn name(&self) -> &str;

  /// Challenge kinds this backend can solve, in preference order.
  /// The renewer passes this list to `CABackend::submit` so CAs
  /// that offer a choice (ACME) can pick a kind the configured
  /// solver actually supports.
  fn supported_kinds(&self) -> &[ChallengeKind];

  /// Whether this backend can satisfy the given challenge. The
  /// renewer fast-fails if the configured backend does not support
  /// the challenge kind the CA returned. Default implementation
  /// matches against `supported_kinds()`; override only if a
  /// backend needs richer per-challenge logic (e.g. domain scope).
  fn supports(&self, challenge: &DcvChallenge) -> bool {
    self.supported_kinds().contains(&challenge.kind())
  }

  /// Publish the challenge response. Idempotent: if the response is
  /// already in place, treat as success.
  async fn publish(&self, challenge: &DcvChallenge) -> Result<()>;

  /// Remove a previously-published challenge response. Idempotent:
  /// if there is nothing to remove, treat as success.
  async fn remove(&self, challenge: &DcvChallenge) -> Result<()>;
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
