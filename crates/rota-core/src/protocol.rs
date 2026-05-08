//! Wire protocol shared between `rotad` (server) and `rota` (client).
//!
//! Line-delimited JSON: one [`Request`] per line in, one [`Response`]
//! per line out, then the connection closes. Tagged enums on both
//! sides so the wire format stays explicit and easy to read with
//! `nc -U /var/run/rota.sock` while debugging.
//!
//! Versioning: any breaking change to a field name or enum variant
//! bumps `PROTOCOL_VERSION`. The server includes the current version
//! in every response so an old client can spot the mismatch and
//! print a useful error rather than deserialise garbage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible wire change.
///
/// v1: initial.
/// v2: `CertSummary.registrar_backend` renamed to
///     `CertSummary.dcv_backend` to track the underlying trait
///     refactor for HTTP-01 support.
pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
  /// Snapshot every cert the daemon manages.
  Status,
  /// Force-run a renewal for one cert. Idempotent: returns the
  /// renewal id whether the renewal succeeded, failed, or was
  /// already in flight.
  Renew { cert_id: String },
  /// Recent renewal-event history for one cert.
  Log {
    cert_id: String,
    #[serde(default)]
    limit: Option<usize>,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
  Status {
    protocol_version: u32,
    certs: Vec<CertSummary>,
  },
  Renew {
    protocol_version: u32,
    renewal_id: String,
    outcome: RenewalOutcome,
  },
  Log {
    protocol_version: u32,
    cert_id: String,
    events: Vec<LogEntry>,
  },
  Error {
    protocol_version: u32,
    message: String,
  },
}

impl Response {
  pub fn error(message: impl Into<String>) -> Self {
    Self::Error {
      protocol_version: PROTOCOL_VERSION,
      message: message.into(),
    }
  }
}

/// One cert's at-a-glance status. The dashboard's table reads from
/// the same shape; the CLI prints it as a one-cert-per-line table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertSummary {
  pub id: String,
  pub description: String,
  pub domains: Vec<String>,
  pub ca_backend: String,
  pub dcv_backend: String,
  pub install_backend: Option<String>,
  pub not_after: Option<DateTime<Utc>>,
  pub days_until_expiry: Option<i64>,
  pub last_renewal_at: Option<DateTime<Utc>>,
  pub last_renewal_status: Option<String>,
  pub last_renewal_error: Option<String>,
}

/// Terminal outcome of a manual renewal request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RenewalOutcome {
  Success,
  Failed,
}

/// One row of the audit log, hydrated for protocol use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
  pub renewal_id: String,
  pub started_at: DateTime<Utc>,
  pub completed_at: Option<DateTime<Utc>>,
  pub status: String,
  pub error: Option<String>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn request_status_roundtrips_as_tagged_json() {
    let r = Request::Status;
    let s = serde_json::to_string(&r).unwrap();
    assert_eq!(s, r#"{"cmd":"status"}"#);
    let back: Request = serde_json::from_str(&s).unwrap();
    assert_eq!(back, r);
  }

  #[test]
  fn request_renew_roundtrips() {
    let r = Request::Renew {
      cert_id: "kushtaka-public".to_owned(),
    };
    let s = serde_json::to_string(&r).unwrap();
    assert_eq!(s, r#"{"cmd":"renew","cert_id":"kushtaka-public"}"#);
    assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
  }

  #[test]
  fn request_log_default_limit_omitted_on_serialize() {
    let r = Request::Log {
      cert_id: "x".to_owned(),
      limit: None,
    };
    let s = serde_json::to_string(&r).unwrap();
    // The protocol round-trips even when `limit` is omitted
    // (serde_json keeps it as null on the wire by default; that's
    // fine and parses back to None).
    let back: Request = serde_json::from_str(&s).unwrap();
    assert_eq!(back, r);
  }

  #[test]
  fn response_error_helper_includes_protocol_version() {
    let r = Response::error("nope");
    match r {
      Response::Error {
        protocol_version,
        message,
      } => {
        assert_eq!(protocol_version, PROTOCOL_VERSION);
        assert_eq!(message, "nope");
      }
      _ => panic!("expected Error variant"),
    }
  }

  #[test]
  fn cert_summary_serializes_with_optional_fields_present() {
    let s = CertSummary {
      id: "x".into(),
      description: "y".into(),
      domains: vec!["example.com".into()],
      ca_backend: "namecheap".into(),
      dcv_backend: "namecheap".into(),
      install_backend: Some("filesystem".into()),
      not_after: None,
      days_until_expiry: None,
      last_renewal_at: None,
      last_renewal_status: None,
      last_renewal_error: None,
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"id\":\"x\""));
    assert!(json.contains("\"install_backend\":\"filesystem\""));
    let back: CertSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
  }
}
