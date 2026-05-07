//! Async-friendly handle to the audit DB.
//!
//! Wraps `rusqlite::Connection` in a `Mutex` and runs every call
//! through `spawn_blocking`. Renewals are infrequent (hourly at most
//! in real deployments) so the contention is negligible; what we
//! care about is that no SQL call ever blocks the tokio runtime.

use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rota_core::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::schema;

/// Lifecycle status of a single renewal attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalStatus {
  InProgress,
  Success,
  Failed,
}

impl RenewalStatus {
  fn as_str(&self) -> &'static str {
    match self {
      Self::InProgress => "in_progress",
      Self::Success => "success",
      Self::Failed => "failed",
    }
  }

  fn parse(s: &str) -> Self {
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

/// One row of the `renewal` table, hydrated.
#[derive(Debug, Clone)]
pub struct RenewalRecord {
  pub id: i64,
  pub cert_id: String,
  pub started_at: DateTime<Utc>,
  pub completed_at: Option<DateTime<Utc>>,
  pub status: RenewalStatus,
  pub error: Option<String>,
}

#[derive(Clone)]
pub struct AuditStore {
  inner: Arc<Mutex<Connection>>,
}

impl AuditStore {
  /// Open or create the audit DB at `path` and apply migrations.
  pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref().to_owned();
    let conn = tokio::task::spawn_blocking(move || -> Result<Connection> {
      if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
          .map_err(|e| Error::Install(format!("audit dir {}: {e}", parent.display())))?;
      }
      let conn = Connection::open(&path).map_err(map_err)?;
      schema::apply(&conn)?;
      Ok(conn)
    })
    .await
    .map_err(|e| Error::Install(format!("audit join: {e}")))??;
    Ok(Self {
      inner: Arc::new(Mutex::new(conn)),
    })
  }

  /// In-memory store for tests.
  pub async fn open_in_memory() -> Result<Self> {
    let conn = tokio::task::spawn_blocking(|| -> Result<Connection> {
      let conn = Connection::open_in_memory().map_err(map_err)?;
      schema::apply(&conn)?;
      Ok(conn)
    })
    .await
    .map_err(|e| Error::Install(format!("audit join: {e}")))??;
    Ok(Self {
      inner: Arc::new(Mutex::new(conn)),
    })
  }

  /// Open a new renewal row in `in_progress` state. Returns the row
  /// id the caller threads through subsequent event/complete calls.
  pub async fn start_renewal(&self, cert_id: &str) -> Result<i64> {
    let cert_id = cert_id.to_owned();
    let now = Utc::now();
    self
      .with_conn(move |c| {
        c.execute(
          "INSERT INTO renewal(cert_id, started_at, status) VALUES (?1, ?2, ?3)",
          rusqlite::params![
            cert_id,
            now.to_rfc3339(),
            RenewalStatus::InProgress.as_str()
          ],
        )
        .map_err(map_err)?;
        Ok(c.last_insert_rowid())
      })
      .await
  }

  /// Append a step event to a renewal.
  pub async fn append_event(
    &self,
    renewal_id: i64,
    kind: EventKind,
    detail: Option<&str>,
  ) -> Result<()> {
    let detail = detail.map(str::to_owned);
    let now = Utc::now();
    self
      .with_conn(move |c| {
        c.execute(
          "INSERT INTO renewal_event(renewal_id, ts, kind, detail) VALUES (?1, ?2, ?3, ?4)",
          rusqlite::params![renewal_id, now.to_rfc3339(), kind.as_str(), detail],
        )
        .map_err(map_err)?;
        Ok(())
      })
      .await
  }

  /// Mark a renewal complete. `error` carries a redacted message on
  /// failure; for success pass `None`.
  pub async fn complete_renewal(
    &self,
    renewal_id: i64,
    status: RenewalStatus,
    error: Option<&str>,
  ) -> Result<()> {
    let error = error.map(str::to_owned);
    let now = Utc::now();
    self
      .with_conn(move |c| {
        c.execute(
          "UPDATE renewal SET completed_at = ?1, status = ?2, error = ?3 WHERE id = ?4",
          rusqlite::params![now.to_rfc3339(), status.as_str(), error, renewal_id],
        )
        .map_err(map_err)?;
        Ok(())
      })
      .await
  }

  /// Look up the most recent renewal for a cert id (any status).
  pub async fn latest_renewal(&self, cert_id: &str) -> Result<Option<RenewalRecord>> {
    let cert_id = cert_id.to_owned();
    self
      .with_conn(move |c| {
        let row = c
          .query_row(
            "SELECT id, cert_id, started_at, completed_at, status, error
             FROM renewal WHERE cert_id = ?1
             ORDER BY id DESC LIMIT 1",
            [cert_id],
            row_to_record,
          )
          .optional()
          .map_err(map_err)?;
        Ok(row)
      })
      .await
  }

  /// Count of renewals for a cert id at each terminal status. Used
  /// by tests; exposed for the dashboard sidebar later.
  pub async fn count_by_status(&self, cert_id: &str) -> Result<(usize, usize)> {
    let cert_id = cert_id.to_owned();
    self
      .with_conn(move |c| {
        let success: i64 = c
          .query_row(
            "SELECT COUNT(*) FROM renewal WHERE cert_id = ?1 AND status = 'success'",
            [&cert_id],
            |r| r.get(0),
          )
          .map_err(map_err)?;
        let failed: i64 = c
          .query_row(
            "SELECT COUNT(*) FROM renewal WHERE cert_id = ?1 AND status = 'failed'",
            [&cert_id],
            |r| r.get(0),
          )
          .map_err(map_err)?;
        Ok((success as usize, failed as usize))
      })
      .await
  }

  async fn with_conn<F, T>(&self, f: F) -> Result<T>
  where
    F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    T: Send + 'static,
  {
    let inner = Arc::clone(&self.inner);
    tokio::task::spawn_blocking(move || {
      let conn = inner.blocking_lock();
      f(&conn)
    })
    .await
    .map_err(|e| Error::Install(format!("audit join: {e}")))?
  }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RenewalRecord> {
  let started: String = row.get(2)?;
  let completed: Option<String> = row.get(3)?;
  let status: String = row.get(4)?;
  Ok(RenewalRecord {
    id: row.get(0)?,
    cert_id: row.get(1)?,
    started_at: parse_ts(&started),
    completed_at: completed.as_deref().map(parse_ts),
    status: RenewalStatus::parse(&status),
    error: row.get(5)?,
  })
}

fn parse_ts(s: &str) -> DateTime<Utc> {
  DateTime::parse_from_rfc3339(s)
    .map(|dt| dt.with_timezone(&Utc))
    .unwrap_or_else(|_| Utc::now())
}

fn map_err(e: rusqlite::Error) -> Error {
  Error::Install(format!("audit sql: {e}"))
}
