//! Cluster coordination primitives.
//!
//! Multiple `rotad` instances can share an audit store and elect a
//! single leader to drive the renewal scheduler. Followers stay
//! quiescent on the schedule side: they exist for cert distribution
//! (lands in a follow-up PR) and for fast leader-failover when the
//! current leader's lock lapses.
//!
//! Election lives behind a trait so single-node deployments use a
//! zero-cost `NoOpCoordinator` that just reports leadership, while
//! clustered deployments plug in a SurrealDB-backed coordinator
//! that holds a lock with a TTL refreshed on a heartbeat.
//!
//! The coordinator owns its own lease-refresh task; the scheduler
//! reads `is_leader()` synchronously on each sweep and skips the
//! sweep if it returns false.

use async_trait::async_trait;

use crate::Result;

/// Cluster coordination trait. Implementations may run a background
/// task to maintain lock state; the scheduler only reads
/// `is_leader()`.
#[async_trait]
pub trait ClusterCoordinator: Send + Sync {
  /// Stable identifier for this coordinator (for logs).
  fn name(&self) -> &str;

  /// Node id this rotad instance announces. Single-node deployments
  /// use the hostname or a synthetic id; cluster members must each
  /// have a unique id so the leadership lock identifies the holder.
  fn node_id(&self) -> &str;

  /// Whether this node currently holds the leader lock. Read on
  /// every scheduler sweep, so the implementation must keep this
  /// cheap (typically an atomic load against an internal cache).
  fn is_leader(&self) -> bool;

  /// Long-running task that maintains the lock. The runtime spawns
  /// this on startup; it should loop forever, refreshing the lease
  /// while leader and re-acquiring when not. A single-node coordinator
  /// can park and return immediately.
  ///
  /// Errors returned here propagate to the daemon's supervisor;
  /// transient failures should be handled internally with backoff.
  async fn run(&self) -> Result<()>;
}
