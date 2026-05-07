use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle state of a managed certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertState {
  /// Configured but never issued; first activation pending.
  Unissued,
  /// CSR submitted; awaiting DCV completion + CA signature.
  Issuing,
  /// DCV TXT record published; polling CA for issuance.
  DcvPending,
  /// Cert issued and installed; healthy.
  Installed,
  /// Last attempt failed; retry scheduled or operator action required.
  Failed,
}

/// A point-in-time view of a managed cert. Stored in the audit DB and
/// surfaced in the dashboard + `rota status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertStatus {
  pub id: String,
  pub domains: Vec<String>,
  pub state: CertState,
  pub not_before: Option<DateTime<Utc>>,
  pub not_after: Option<DateTime<Utc>>,
  pub last_renewal_at: Option<DateTime<Utc>>,
  pub last_error: Option<String>,
}

impl CertStatus {
  /// Days until `not_after`, or `None` if never issued.
  pub fn days_until_expiry(&self, now: DateTime<Utc>) -> Option<i64> {
    self.not_after.map(|exp| (exp - now).num_days())
  }

  /// Whether this cert is within the renewal window.
  pub fn is_renewal_due(&self, now: DateTime<Utc>, threshold_days: i64) -> bool {
    self
      .days_until_expiry(now)
      .map(|d| d <= threshold_days)
      .unwrap_or(true)
  }
}
