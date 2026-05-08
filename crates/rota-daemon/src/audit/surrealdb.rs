//! SurrealDB-backed audit store.
//!
//! Wraps the user's `oneiriq-surql` (`surql-rs`) Rust client. Schema
//! is defined in `surrealdb_initial.surql` and applied at connect
//! time via `DEFINE TABLE IF NOT EXISTS` so reconnecting an existing
//! database is a no-op. Renewal IDs are SurrealDB's native
//! `table:id` literal strings (e.g. `renewal:01J5...`) threaded back
//! through the `RenewalId` opaque type.
//!
//! For embedded testing the `mem://` engine runs the whole DB
//! in-process with no external service; production deployments will
//! typically point at a `ws://` or `wss://` endpoint.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rota_core::config::AuditSpec;
use rota_core::{Error, Result};
use serde_json::{json, Value};
use surql::connection::auth::RootCredentials;
use surql::connection::{ConnectionConfig, DatabaseClient};

use super::types::{
  AuditStore, EventKind, IssuedCertRecord, RenewalId, RenewalRecord, RenewalStatus,
};

const SCHEMA_SURQL: &str = include_str!("surrealdb_initial.surql");

pub struct SurrealAuditStore {
  client: Arc<DatabaseClient>,
}

impl SurrealAuditStore {
  /// Construct from the parsed `AuditSpec::Surrealdb` config block.
  /// Reads the password file (if any) and signs in with root creds
  /// before applying the schema. Embedded URLs (`mem://`, `file://`)
  /// skip the signin step.
  pub async fn from_spec(spec: &AuditSpec) -> Result<Self> {
    let client = open_client(spec).await?;
    apply_schema(&client).await?;
    Ok(Self {
      client: Arc::new(client),
    })
  }

  /// Embedded in-memory store for tests.
  pub async fn open_in_memory() -> Result<Self> {
    let config = ConnectionConfig::builder()
      .url("mem://")
      .namespace("rota")
      .database("audit")
      .build()
      .map_err(map_err)?;
    let client = DatabaseClient::new(config).map_err(map_err)?;
    client.connect().await.map_err(map_err)?;
    apply_schema(&client).await?;
    Ok(Self {
      client: Arc::new(client),
    })
  }

  /// Shared handle on the underlying `DatabaseClient`. Used by the
  /// cluster coordinator so audit + cluster state can live in the
  /// same SurrealDB connection, which matters for tests against
  /// `mem://` (each `mem://` connect produces an isolated database).
  pub fn client_arc(&self) -> Arc<DatabaseClient> {
    Arc::clone(&self.client)
  }
}

/// Open a SurrealDB client from a parsed audit spec. Public so the
/// cluster coordinator can construct a sibling client that points
/// at the same endpoint + namespace + database.
pub async fn open_client(spec: &AuditSpec) -> Result<DatabaseClient> {
  let AuditSpec::Surrealdb {
    endpoint,
    namespace,
    database,
    username,
    password_file,
  } = spec
  else {
    return Err(Error::ConfigInvalid(
      "open_client called with non-surrealdb audit spec".into(),
    ));
  };

  let mut builder = ConnectionConfig::builder()
    .url(endpoint.as_str())
    .namespace(namespace.as_str())
    .database(database.as_str());
  if let Some(user) = username {
    builder = builder.username(user.as_str());
  }
  let config = builder
    .build()
    .map_err(|e| Error::ConfigInvalid(format!("surrealdb config: {e}")))?;
  let client = DatabaseClient::new(config).map_err(map_err)?;
  client.connect().await.map_err(map_err)?;

  if let (Some(user), Some(file)) = (username, password_file) {
    let pwd = tokio::fs::read_to_string(file)
      .await
      .map_err(|e| Error::ConfigInvalid(format!("read {}: {e}", file.display())))?
      .trim()
      .to_owned();
    client
      .signin(&RootCredentials::new(user.clone(), pwd))
      .await
      .map_err(map_err)?;
  }

  Ok(client)
}

pub async fn apply_schema(client: &DatabaseClient) -> Result<()> {
  client.query(SCHEMA_SURQL).await.map_err(map_err)?;
  Ok(())
}

#[async_trait]
impl AuditStore for SurrealAuditStore {
  fn name(&self) -> &str {
    "surrealdb"
  }

  async fn start_renewal(&self, cert_id: &str) -> Result<RenewalId> {
    let mut vars = BTreeMap::new();
    vars.insert("cert_id".to_owned(), Value::String(cert_id.to_owned()));
    vars.insert(
      "started_at".to_owned(),
      Value::String(Utc::now().to_rfc3339()),
    );
    vars.insert(
      "status".to_owned(),
      Value::String(RenewalStatus::InProgress.as_str().to_owned()),
    );

    let raw = client_query(
      &self.client,
      "CREATE renewal CONTENT {
         cert_id: $cert_id,
         started_at: <datetime>$started_at,
         status: $status
       };",
      vars,
    )
    .await?;

    let id = first_string_field(&raw, "id")
      .ok_or_else(|| Error::Install("surrealdb create renewal returned no id".into()))?;
    Ok(RenewalId(id))
  }

  async fn append_event(
    &self,
    renewal_id: &RenewalId,
    kind: EventKind,
    detail: Option<&str>,
  ) -> Result<()> {
    let mut vars = BTreeMap::new();
    vars.insert("renewal_id".to_owned(), Value::String(renewal_id.0.clone()));
    vars.insert("ts".to_owned(), Value::String(Utc::now().to_rfc3339()));
    vars.insert("kind".to_owned(), Value::String(kind.as_str().to_owned()));

    // SurrealDB's `option<T>` accepts `NONE` (the explicit absence
    // marker) but rejects JSON `NULL`. When `detail` is `None`, omit
    // the field from the CONTENT block so the schema default (NONE)
    // takes over rather than passing a null that would coerce-fail.
    let surql = if let Some(d) = detail {
      vars.insert("detail".to_owned(), Value::String(d.to_owned()));
      "CREATE renewal_event CONTENT {
         renewal_id: <record>$renewal_id,
         ts: <datetime>$ts,
         kind: $kind,
         detail: $detail
       };"
    } else {
      "CREATE renewal_event CONTENT {
         renewal_id: <record>$renewal_id,
         ts: <datetime>$ts,
         kind: $kind
       };"
    };

    client_query(&self.client, surql, vars).await?;
    Ok(())
  }

  async fn complete_renewal(
    &self,
    renewal_id: &RenewalId,
    status: RenewalStatus,
    error: Option<&str>,
  ) -> Result<()> {
    let mut vars = BTreeMap::new();
    vars.insert("renewal_id".to_owned(), Value::String(renewal_id.0.clone()));
    vars.insert(
      "completed_at".to_owned(),
      Value::String(Utc::now().to_rfc3339()),
    );
    vars.insert(
      "status".to_owned(),
      Value::String(status.as_str().to_owned()),
    );

    // Same NONE-vs-NULL story as `append_event`: when `error` is
    // None, emit the SET without the error column so the existing
    // value (NONE) stays put.
    let surql = if let Some(e) = error {
      vars.insert("error".to_owned(), Value::String(e.to_owned()));
      "UPDATE <record>$renewal_id SET
         completed_at = <datetime>$completed_at,
         status = $status,
         error = $error;"
    } else {
      "UPDATE <record>$renewal_id SET
         completed_at = <datetime>$completed_at,
         status = $status;"
    };

    client_query(&self.client, surql, vars).await?;
    Ok(())
  }

  async fn latest_renewal(&self, cert_id: &str) -> Result<Option<RenewalRecord>> {
    let mut vars = BTreeMap::new();
    vars.insert("cert_id".to_owned(), Value::String(cert_id.to_owned()));

    let raw = client_query(
      &self.client,
      "SELECT id, cert_id, started_at, completed_at, status, error
       FROM renewal
       WHERE cert_id = $cert_id
       ORDER BY started_at DESC
       LIMIT 1;",
      vars,
    )
    .await?;

    let Some(row) = first_row(&raw) else {
      return Ok(None);
    };
    Ok(Some(row_to_record(row)?))
  }

  async fn count_by_status(&self, cert_id: &str) -> Result<(usize, usize)> {
    let mut vars = BTreeMap::new();
    vars.insert("cert_id".to_owned(), Value::String(cert_id.to_owned()));

    let raw = client_query(
      &self.client,
      "SELECT
         count(status = 'success') AS ok,
         count(status = 'failed')  AS failed
       FROM renewal
       WHERE cert_id = $cert_id
       GROUP ALL;",
      vars,
    )
    .await?;

    let row = first_row(&raw)
      .cloned()
      .unwrap_or_else(|| json!({"ok": 0, "failed": 0}));
    let ok = row.get("ok").and_then(Value::as_u64).unwrap_or(0) as usize;
    let failed = row.get("failed").and_then(Value::as_u64).unwrap_or(0) as usize;
    Ok((ok, failed))
  }

  async fn record_issued_cert(
    &self,
    cert_id: &str,
    cert_pem: &str,
    chain_pem: &str,
    issued_at: DateTime<Utc>,
  ) -> Result<()> {
    let mut vars = BTreeMap::new();
    vars.insert("cert_id".to_owned(), Value::String(cert_id.to_owned()));
    vars.insert("cert_pem".to_owned(), Value::String(cert_pem.to_owned()));
    vars.insert("chain_pem".to_owned(), Value::String(chain_pem.to_owned()));
    vars.insert(
      "issued_at".to_owned(),
      Value::String(issued_at.to_rfc3339()),
    );

    client_query(
      &self.client,
      "CREATE issued_cert CONTENT {
         cert_id: $cert_id,
         cert_pem: $cert_pem,
         chain_pem: $chain_pem,
         issued_at: <datetime>$issued_at
       };",
      vars,
    )
    .await?;
    Ok(())
  }

  async fn latest_issued_cert(&self, cert_id: &str) -> Result<Option<IssuedCertRecord>> {
    let mut vars = BTreeMap::new();
    vars.insert("cert_id".to_owned(), Value::String(cert_id.to_owned()));

    let raw = client_query(
      &self.client,
      "SELECT cert_id, cert_pem, chain_pem, issued_at
       FROM issued_cert
       WHERE cert_id = $cert_id
       ORDER BY issued_at DESC
       LIMIT 1;",
      vars,
    )
    .await?;

    let Some(row) = first_row(&raw) else {
      return Ok(None);
    };
    let cert_id = row
      .get("cert_id")
      .and_then(Value::as_str)
      .ok_or_else(|| Error::Install("issued_cert row missing cert_id".into()))?
      .to_owned();
    let cert_pem = row
      .get("cert_pem")
      .and_then(Value::as_str)
      .ok_or_else(|| Error::Install("issued_cert row missing cert_pem".into()))?
      .to_owned();
    let chain_pem = row
      .get("chain_pem")
      .and_then(Value::as_str)
      .ok_or_else(|| Error::Install("issued_cert row missing chain_pem".into()))?
      .to_owned();
    let issued_at = row
      .get("issued_at")
      .and_then(value_as_string)
      .as_deref()
      .map(parse_ts)
      .ok_or_else(|| Error::Install("issued_cert row missing issued_at".into()))?;
    Ok(Some(IssuedCertRecord {
      cert_id,
      cert_pem,
      chain_pem,
      issued_at,
    }))
  }
}

async fn client_query(
  client: &DatabaseClient,
  surql: &str,
  vars: BTreeMap<String, Value>,
) -> Result<Value> {
  client.query_with_vars(surql, vars).await.map_err(map_err)
}

/// SurrealDB returns query results as a JSON array with one entry per
/// statement. Helpers below pluck the first row of the first
/// statement, which is what every method here expects.
fn first_row(raw: &Value) -> Option<&Value> {
  let stmts = raw.as_array()?;
  let first_stmt = stmts.first()?;
  match first_stmt {
    Value::Array(rows) => rows.first(),
    Value::Object(_) => Some(first_stmt),
    _ => None,
  }
}

fn first_string_field(raw: &Value, field: &str) -> Option<String> {
  let row = first_row(raw)?;
  let value = row.get(field)?;
  match value {
    Value::String(s) => Some(s.clone()),
    other => Some(other.to_string().trim_matches('"').to_owned()),
  }
}

fn row_to_record(row: &Value) -> Result<RenewalRecord> {
  let id = row
    .get("id")
    .and_then(value_as_string)
    .ok_or_else(|| Error::Install("renewal row missing id".into()))?;
  let cert_id = row
    .get("cert_id")
    .and_then(Value::as_str)
    .ok_or_else(|| Error::Install("renewal row missing cert_id".into()))?
    .to_owned();
  let started_at = row
    .get("started_at")
    .and_then(value_as_string)
    .as_deref()
    .map(parse_ts)
    .ok_or_else(|| Error::Install("renewal row missing started_at".into()))?;
  let completed_at = row
    .get("completed_at")
    .filter(|v| !v.is_null())
    .and_then(value_as_string)
    .as_deref()
    .map(parse_ts);
  let status = row
    .get("status")
    .and_then(Value::as_str)
    .map(RenewalStatus::parse)
    .unwrap_or(RenewalStatus::InProgress);
  let error = row.get("error").and_then(Value::as_str).map(str::to_owned);

  Ok(RenewalRecord {
    id: RenewalId(id),
    cert_id,
    started_at,
    completed_at,
    status,
    error,
  })
}

/// SurrealDB record IDs may serialise as either a JSON string
/// (`"renewal:abc"`) or an object with `tb` / `id` fields depending
/// on driver version. Accept both.
fn value_as_string(v: &Value) -> Option<String> {
  match v {
    Value::String(s) => Some(s.clone()),
    Value::Object(map) => {
      if let (Some(Value::String(tb)), Some(id)) = (map.get("tb"), map.get("id")) {
        Some(format!("{tb}:{}", id_to_string(id)))
      } else {
        None
      }
    }
    _ => None,
  }
}

fn id_to_string(v: &Value) -> String {
  match v {
    Value::String(s) => s.clone(),
    Value::Number(n) => n.to_string(),
    other => other.to_string(),
  }
}

fn parse_ts(s: &str) -> DateTime<Utc> {
  DateTime::parse_from_rfc3339(s)
    .map(|dt| dt.with_timezone(&Utc))
    .unwrap_or_else(|_| Utc::now())
}

fn map_err(e: impl std::fmt::Display) -> Error {
  Error::Install(format!("surrealdb audit: {e}"))
}
