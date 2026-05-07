//! Backend-independent audit types and the `AuditStore` trait.
//!
//! Renewal IDs are opaque strings so each backend can use its native
//! identifier shape: the SQLite impl stringifies `last_insert_rowid`,
//! the SurrealDB impl returns the record's `table:id` literal. The
//! caller threads the `RenewalId` through the pipeline without ever
//! inspecting it.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rota_core::Result;

/// Lifecycle status of a single renewal attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalStatus {
  InProgress,
  Success,
  Failed,
}

impl RenewalStatus {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::InProgress => "in_progress",
      Self::Success => "success",
      Self::Failed => "failed",
    }
  }

  pub fn parse(s: &str) -> Self {
    match s {
      "success" => Self::Success,
      "failed" => Self::Failed,
      _ => Self::InProgress,
    }
  }
}

/// Discrete steps the renewal pipeline emits as it progresses.
/// Adding a new step is a new variant plus an arm in `as_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
  CsrGenerated,
  CaSubmitted,
  DcvPublished,
  CertIssued,
  CertInstalled,
  DcvRemoved,
  Error,
}

impl EventKind {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::CsrGenerated => "csr_generated",
      Self::CaSubmitted => "ca_submitted",
      Self::DcvPublished => "dcv_published",
      Self::CertIssued => "cert_issued",
      Self::CertInstalled => "cert_installed",
      Self::DcvRemoved => "dcv_removed",
      Self::Error => "error",
    }
  }
}

/// Opaque renewal identifier. Each backend picks its own format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalId(pub String);

impl RenewalId {
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl From<String> for RenewalId {
  fn from(s: String) -> Self {
    Self(s)
  }
}

/// One row of the renewal table, hydrated.
#[derive(Debug, Clone)]
pub struct RenewalRecord {
  pub id: RenewalId,
  pub cert_id: String,
  pub started_at: DateTime<Utc>,
  pub completed_at: Option<DateTime<Utc>>,
  pub status: RenewalStatus,
  pub error: Option<String>,
}

/// Backend-independent audit log. The trait is dyn-safe so callers
/// hold `Arc<dyn AuditStore>` without caring which backend was wired.
#[async_trait]
pub trait AuditStore: Send + Sync {
  /// Stable identifier for this backend (for logs).
  fn name(&self) -> &str;

  /// Open a new renewal row in `in_progress` state. Returns the id
  /// the caller threads through subsequent event/complete calls.
  async fn start_renewal(&self, cert_id: &str) -> Result<RenewalId>;

  /// Append a step event to a renewal.
  async fn append_event(
    &self,
    renewal_id: &RenewalId,
    kind: EventKind,
    detail: Option<&str>,
  ) -> Result<()>;

  /// Mark a renewal complete. `error` carries a redacted message on
  /// failure; for success pass `None`.
  async fn complete_renewal(
    &self,
    renewal_id: &RenewalId,
    status: RenewalStatus,
    error: Option<&str>,
  ) -> Result<()>;

  /// Look up the most recent renewal for a cert id (any status).
  async fn latest_renewal(&self, cert_id: &str) -> Result<Option<RenewalRecord>>;

  /// `(success, failed)` count for a cert id.
  async fn count_by_status(&self, cert_id: &str) -> Result<(usize, usize)>;
}
