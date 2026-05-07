//! Schema migrations for the SQLite audit DB.
//!
//! Migrations run in order at every connection open. Each one is
//! idempotent (`CREATE TABLE IF NOT EXISTS` etc.) so reopening an
//! already-current DB is a no-op. Bumping the on-disk version is
//! handled by writing the highest applied migration id into
//! `schema_version`. The SurrealDB backend has its own schema flow
//! and does not share this module.

use rota_core::{Error, Result};
use rusqlite::Connection;

/// Versioned migration. `id` strictly increases.
struct Migration {
  id: i32,
  sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
  id: 1,
  sql: include_str!("sqlite_initial.sql"),
}];

pub fn apply(conn: &Connection) -> Result<()> {
  conn
    .execute_batch(
      "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL PRIMARY KEY);",
    )
    .map_err(map_err)?;

  let current: i32 = conn
    .query_row(
      "SELECT COALESCE(MAX(version), 0) FROM schema_version",
      [],
      |r| r.get(0),
    )
    .map_err(map_err)?;

  for m in MIGRATIONS.iter().filter(|m| m.id > current) {
    conn.execute_batch(m.sql).map_err(map_err)?;
    conn
      .execute("INSERT INTO schema_version(version) VALUES (?1)", [m.id])
      .map_err(map_err)?;
  }
  Ok(())
}

fn map_err(e: rusqlite::Error) -> Error {
  Error::Install(format!("audit schema: {e}"))
}
