//! Cluster coordinator implementations.
//!
//! One impl today (PR3a scope):
//!
//! * [`NoOpCoordinator`]: zero-cost single-node default. Always
//!   reports leadership; the `run` task parks forever. Used when
//!   the operator omits the top-level `cluster:` config block.
//!
//! The SurrealDB-backed coordinator (real lock with TTL refresh,
//! holds a `cluster_lock:singleton` row, drives failover) lands in
//! the follow-up PR alongside cert distribution to followers.

mod no_op;

pub use no_op::NoOpCoordinator;
