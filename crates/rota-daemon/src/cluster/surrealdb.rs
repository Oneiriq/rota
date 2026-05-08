//! SurrealDB-backed cluster coordinator.
//!
//! Holds a singleton row at `cluster_lock:singleton` with `holder`,
//! `acquired_at`, and `expires_at` fields. The lock is acquirable
//! when the row does not exist, when it has lapsed (`expires_at` is
//! in the past), or when the current holder is us (refresh path).
//!
//! The acquire / refresh transaction is a single SurQL block so the
//! check-then-write is atomic against another rotad instance racing
//! for the same lock; SurrealDB's serialisable default isolation is
//! enough for this pattern.
//!
//! Lease cadence: the lease loop refreshes at lease/3 so a single
//! transient failure (one missed refresh) does not lapse the lease.
//! With the default 60s lease that's a 20s refresh cadence and a
//! ~60s worst-case failover window.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rota_core::cluster::ClusterCoordinator;
use rota_core::config::AuditSpec;
use rota_core::{Error, Result};
use serde_json::Value;
use surql::connection::DatabaseClient;
use tracing::{debug, info, warn};

use crate::audit::surrealdb::{apply_schema, open_client};

const ACQUIRE_OR_REFRESH_SURQL: &str = r#"
BEGIN TRANSACTION;
LET $now = time::now();
LET $existing = (SELECT * FROM ONLY cluster_lock:singleton);
IF $existing == NONE OR $existing.expires_at < $now OR $existing.holder = $node_id {
  UPSERT cluster_lock:singleton CONTENT {
    holder: $node_id,
    acquired_at: $now,
    expires_at: $now + duration::from_secs($lease_secs),
  };
  RETURN { acquired: true };
} ELSE {
  RETURN { acquired: false, holder: $existing.holder };
};
COMMIT TRANSACTION;
"#;

pub struct SurrealClusterCoordinator {
  client: Arc<DatabaseClient>,
  node_id: String,
  lease: Duration,
  is_leader: AtomicBool,
}

impl SurrealClusterCoordinator {
  /// Construct from the parsed `AuditSpec::Surrealdb` block. Opens
  /// a sibling SurrealDB connection (separate from the audit
  /// store's). Production deployments that point at a `ws://`
  /// SurrealDB share the underlying server; embedded `mem://`
  /// connections each get their own database, so for in-process
  /// tests use [`with_client`] instead.
  pub async fn from_audit_spec(spec: &AuditSpec, node_id: String, lease: Duration) -> Result<Self> {
    let client = open_client(spec).await?;
    apply_schema(&client).await?;
    Ok(Self::with_client(Arc::new(client), node_id, lease))
  }

  /// Construct from a pre-existing client. Used by tests so multiple
  /// coordinators can share one in-memory database.
  pub fn with_client(client: Arc<DatabaseClient>, node_id: String, lease: Duration) -> Self {
    Self {
      client,
      node_id,
      lease,
      is_leader: AtomicBool::new(false),
    }
  }

  /// Single attempt to acquire or refresh the lock.
  pub async fn try_acquire_or_refresh(&self) -> Result<bool> {
    let mut vars = BTreeMap::new();
    vars.insert("node_id".to_owned(), Value::String(self.node_id.clone()));
    vars.insert(
      "lease_secs".to_owned(),
      Value::Number(self.lease.as_secs().into()),
    );

    let raw = self
      .client
      .query_with_vars(ACQUIRE_OR_REFRESH_SURQL, vars)
      .await
      .map_err(|e| Error::ConfigInvalid(format!("cluster lock query: {}", err_string(&e))))?;

    Ok(parse_acquired(&raw))
  }
}

#[async_trait]
impl ClusterCoordinator for SurrealClusterCoordinator {
  fn name(&self) -> &str {
    "surrealdb"
  }

  fn node_id(&self) -> &str {
    &self.node_id
  }

  fn is_leader(&self) -> bool {
    self.is_leader.load(Ordering::Acquire)
  }

  async fn run(&self) -> Result<()> {
    let refresh_interval = self.lease / 3;
    info!(
      node = %self.node_id,
      lease_s = self.lease.as_secs(),
      refresh_s = refresh_interval.as_secs(),
      "cluster: lease loop starting"
    );
    loop {
      match self.try_acquire_or_refresh().await {
        Ok(true) => {
          let was_leader = self.is_leader.swap(true, Ordering::AcqRel);
          if !was_leader {
            info!(node = %self.node_id, "cluster: acquired leader lock");
          } else {
            debug!(node = %self.node_id, "cluster: refreshed leader lock");
          }
        }
        Ok(false) => {
          let was_leader = self.is_leader.swap(false, Ordering::AcqRel);
          if was_leader {
            warn!(node = %self.node_id, "cluster: lost leader lock; demoted to follower");
          } else {
            debug!(node = %self.node_id, "cluster: still follower");
          }
        }
        Err(err) => {
          // Network/db hiccup: assume follower until we can check
          // again. The next sweep is short (refresh_interval).
          let was_leader = self.is_leader.swap(false, Ordering::AcqRel);
          if was_leader {
            warn!(
              node = %self.node_id,
              error = %err,
              "cluster: lock check failed while leader; demoted defensively"
            );
          } else {
            warn!(node = %self.node_id, error = %err, "cluster: lock check failed");
          }
        }
      }
      tokio::time::sleep(refresh_interval).await;
    }
  }
}

fn parse_acquired(raw: &Value) -> bool {
  // Multi-statement SurQL response: array of per-statement results.
  // The IF/ELSE block returns the `{ acquired: bool }` object; with
  // BEGIN/COMMIT framing it lands in the second-to-last slot. Walk
  // every statement result looking for the `acquired` field.
  fn walk(v: &Value) -> Option<bool> {
    match v {
      Value::Object(o) => o.get("acquired").and_then(Value::as_bool),
      Value::Array(arr) => arr.iter().find_map(walk),
      _ => None,
    }
  }
  walk(raw).unwrap_or(false)
}

fn err_string<E: std::fmt::Display>(e: &E) -> String {
  e.to_string()
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;
  use surql::connection::ConnectionConfig;

  /// Open one in-memory SurrealDB connection and apply the schema.
  /// Multiple coordinators wrap the same Arc<DatabaseClient> so they
  /// see the same database state.
  async fn shared_client() -> Arc<DatabaseClient> {
    let config = ConnectionConfig::builder()
      .url("mem://")
      .namespace("rota")
      .database("audit")
      .build()
      .unwrap();
    let client = DatabaseClient::new(config).unwrap();
    client.connect().await.unwrap();
    apply_schema(&client).await.unwrap();
    Arc::new(client)
  }

  #[tokio::test]
  async fn first_attempt_acquires_lock() {
    let client = shared_client().await;
    let coord =
      SurrealClusterCoordinator::with_client(client, "node-a".to_owned(), Duration::from_secs(60));
    assert!(coord.try_acquire_or_refresh().await.unwrap());
  }

  #[tokio::test]
  async fn second_node_cannot_acquire_while_first_holds() {
    let client = shared_client().await;
    let a = SurrealClusterCoordinator::with_client(
      Arc::clone(&client),
      "node-a".to_owned(),
      Duration::from_secs(60),
    );
    let b = SurrealClusterCoordinator::with_client(
      Arc::clone(&client),
      "node-b".to_owned(),
      Duration::from_secs(60),
    );

    assert!(a.try_acquire_or_refresh().await.unwrap(), "a acquires");
    assert!(
      !b.try_acquire_or_refresh().await.unwrap(),
      "b denied while a holds"
    );
  }

  #[tokio::test]
  async fn holder_can_refresh() {
    let client = shared_client().await;
    let a =
      SurrealClusterCoordinator::with_client(client, "node-a".to_owned(), Duration::from_secs(60));
    assert!(a.try_acquire_or_refresh().await.unwrap(), "a acquires");
    assert!(
      a.try_acquire_or_refresh().await.unwrap(),
      "a refreshes (still holder)"
    );
  }

  #[tokio::test]
  async fn second_node_acquires_after_lease_expires() {
    let client = shared_client().await;
    let a = SurrealClusterCoordinator::with_client(
      Arc::clone(&client),
      "node-a".to_owned(),
      Duration::from_secs(1),
    );
    let b = SurrealClusterCoordinator::with_client(
      Arc::clone(&client),
      "node-b".to_owned(),
      Duration::from_secs(60),
    );

    assert!(a.try_acquire_or_refresh().await.unwrap(), "a acquires");
    // Wait past a's 1-second lease.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
      b.try_acquire_or_refresh().await.unwrap(),
      "b acquires after a's lease lapses"
    );
  }

  #[test]
  fn parse_acquired_handles_typical_shape() {
    // SurrealDB 3.x typically returns an array of per-statement
    // results. The acquire path puts {"acquired": true} somewhere
    // in there.
    let response = serde_json::json!([null, null, {"acquired": true}, null]);
    assert!(parse_acquired(&response));

    let response = serde_json::json!([{"acquired": false, "holder": "other"}]);
    assert!(!parse_acquired(&response));

    let response = serde_json::json!({"acquired": true});
    assert!(parse_acquired(&response));
  }
}
