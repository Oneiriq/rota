use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use x509_parser::pem::parse_x509_pem;

use crate::{Error, Result};

/// Parse the `notAfter` field from a PEM-encoded X.509 certificate.
///
/// Returns the validity end as a UTC `DateTime`. Used by the
/// scheduler to decide whether a cert is within its renewal window,
/// and by the dashboard to surface days-remaining.
pub fn parse_not_after(pem: &str) -> Result<DateTime<Utc>> {
  let (_, pem) =
    parse_x509_pem(pem.as_bytes()).map_err(|e| Error::Install(format!("parse pem: {e}")))?;
  let cert = pem
    .parse_x509()
    .map_err(|e| Error::Install(format!("parse x509: {e}")))?;
  let ts = cert.tbs_certificate.validity.not_after.timestamp();
  DateTime::<Utc>::from_timestamp(ts, 0)
    .ok_or_else(|| Error::Install(format!("notAfter timestamp out of range: {ts}")))
}

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

#[cfg(test)]
mod tests {
  use super::*;
  use rcgen::{CertificateParams, KeyPair};

  fn issue_test_cert(days_valid: u32) -> String {
    let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(days_valid as i64);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.pem()
  }

  #[test]
  fn parse_not_after_roundtrips_within_a_minute() {
    let pem = issue_test_cert(30);
    let parsed = parse_not_after(&pem).unwrap();
    let expected = Utc::now() + chrono::Duration::days(30);
    let drift = (parsed - expected).num_seconds().abs();
    assert!(drift < 60, "parsed notAfter drifted {drift}s from expected");
  }

  #[test]
  fn parse_not_after_rejects_garbage_input() {
    assert!(parse_not_after("not a pem").is_err());
    assert!(
      parse_not_after("-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----\n").is_err()
    );
  }

  #[test]
  fn is_renewal_due_with_freshly_parsed_cert() {
    let pem = issue_test_cert(60);
    let not_after = parse_not_after(&pem).unwrap();
    let status = CertStatus {
      id: "x".to_owned(),
      domains: vec!["example.com".into()],
      state: CertState::Installed,
      not_before: None,
      not_after: Some(not_after),
      last_renewal_at: None,
      last_error: None,
    };
    assert!(!status.is_renewal_due(Utc::now(), 30));
    assert!(status.is_renewal_due(Utc::now(), 70));
  }
}
