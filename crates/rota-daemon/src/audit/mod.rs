//! Audit log surface for renewal pipelines.
//!
//! The trait `AuditStore` defines the verbs every backend implements:
//! open a renewal row, append step events as the pipeline walks, mark
//! it complete with a status. Two impls ship today:
//!
//! - [`SqliteAuditStore`]: zero-config single-file SQLite via
//!   `rusqlite` + `spawn_blocking`. Default for OSS portability;
//!   nothing to provision, the daemon owns the file.
//! - [`SurrealAuditStore`]: SurrealDB via the `surql` (oneiriq-surql)
//!   crate. Native record-id schema, queryable from the same DB
//!   self-hosters may already run for adjacent projects.
//!
//! Pick at config-load time via the top-level `audit:` block in
//! `rota.yaml`; the rest of the daemon holds an `Arc<dyn AuditStore>`
//! and doesn't care which backend is wired underneath.

mod schema;
mod sqlite;
#[cfg(feature = "surrealdb")]
mod surrealdb;
mod types;

pub use sqlite::SqliteAuditStore;
#[cfg(feature = "surrealdb")]
pub use surrealdb::SurrealAuditStore;
pub use types::{AuditStore, EventKind, RenewalId, RenewalRecord, RenewalStatus};

#[cfg(test)]
mod tests;
