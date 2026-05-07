//! SQLite-backed audit store.
//!
//! Wraps `rusqlite::Connection` in a `Mutex` and runs every call
//! through `spawn_blocking`. Renewals are infrequent (hourly at most
//! in real deployments) so the contention is negligible; what we
//! care about is that no SQL call ever blocks the tokio runtime.
//! Default backend in rota.yaml: zero-config, single-file, no
//! external service to provision.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rota_core::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::schema;
use super::types::{AuditStore, EventKind, RenewalId, RenewalRecord, RenewalStatus};

#[derive(Clone)]
pub struct SqliteAuditStore {
  inner: Arc<Mutex<Connection>>,
}

impl SqliteAuditStore {
  /// Open or create the audit DB at `path` and apply migrations.
  ///
  /// The parent directory is created with mode 0700 and the DB file
  /// itself is chmodded to 0600 if it didn't already exist or was
  /// world-readable. The audit log carries renewal history and any
  /// error strings the renewer recorded; treating it like a private
  /// key file is the right default.
  pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref().to_owned();
    let conn = tokio::task::spawn_blocking(move || -> Result<Connection> {
      use std::os::unix::fs::PermissionsExt;
      if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
          .map_err(|e| Error::Install(format!("audit dir {}: {e}", parent.display())))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
      }
      let conn = Connection::open(&path).map_err(map_err)?;
      let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
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

#[async_trait]
impl AuditStore for SqliteAuditStore {
  fn name(&self) -> &str {
    "sqlite"
  }

  async fn start_renewal(&self, cert_id: &str) -> Result<RenewalId> {
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
        Ok(RenewalId(c.last_insert_rowid().to_string()))
      })
      .await
  }

  async fn append_event(
    &self,
    renewal_id: &RenewalId,
    kind: EventKind,
    detail: Option<&str>,
  ) -> Result<()> {
    let id_i64 = parse_rowid(renewal_id)?;
    let detail = detail.map(str::to_owned);
    let kind_str = kind.as_str();
    let now = Utc::now();
    self
      .with_conn(move |c| {
        c.execute(
          "INSERT INTO renewal_event(renewal_id, ts, kind, detail) VALUES (?1, ?2, ?3, ?4)",
          rusqlite::params![id_i64, now.to_rfc3339(), kind_str, detail],
        )
        .map_err(map_err)?;
        Ok(())
      })
      .await
  }

  async fn complete_renewal(
    &self,
    renewal_id: &RenewalId,
    status: RenewalStatus,
    error: Option<&str>,
  ) -> Result<()> {
    let id_i64 = parse_rowid(renewal_id)?;
    let error = error.map(str::to_owned);
    let status_str = status.as_str();
    let now = Utc::now();
    self
      .with_conn(move |c| {
        c.execute(
          "UPDATE renewal SET completed_at = ?1, status = ?2, error = ?3 WHERE id = ?4",
          rusqlite::params![now.to_rfc3339(), status_str, error, id_i64],
        )
        .map_err(map_err)?;
        Ok(())
      })
      .await
  }

  async fn latest_renewal(&self, cert_id: &str) -> Result<Option<RenewalRecord>> {
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

  async fn count_by_status(&self, cert_id: &str) -> Result<(usize, usize)> {
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
}

fn parse_rowid(id: &RenewalId) -> Result<i64> {
  id.0
    .parse()
    .map_err(|_| Error::Install(format!("invalid sqlite renewal id: {}", id.0)))
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RenewalRecord> {
  let started: String = row.get(2)?;
  let completed: Option<String> = row.get(3)?;
  let status: String = row.get(4)?;
  let id: i64 = row.get(0)?;
  Ok(RenewalRecord {
    id: RenewalId(id.to_string()),
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
