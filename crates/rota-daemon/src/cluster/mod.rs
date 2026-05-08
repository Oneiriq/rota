//! Cluster coordinator implementations.
//!
//! Two impls today:
//!
//! * [`NoOpCoordinator`]: zero-cost single-node default. Always
//!   reports leadership; the `run` task parks forever. Used when
//!   the operator omits the top-level `cluster:` config block.
//! * [`SurrealClusterCoordinator`] (gated on the `surrealdb`
//!   feature): real lock with TTL refresh against a SurrealDB-
//!   backed audit store. Holds a `cluster_lock:singleton` row that
//!   carries the holder + lease expiry; the `run` task refreshes
//!   the lock at lease/3 cadence. Used when the operator sets
//!   `cluster.enabled = true` and runs SurrealDB audit.
//!
//! Cert distribution to followers (the install-side half of
//! federation) lands in a separate follow-up.

mod no_op;
#[cfg(feature = "surrealdb")]
mod surrealdb;

pub use no_op::NoOpCoordinator;
#[cfg(feature = "surrealdb")]
pub use surrealdb::SurrealClusterCoordinator;
