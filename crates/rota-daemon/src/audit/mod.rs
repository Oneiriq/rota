//! SQLite-backed audit log for renewal pipelines.
//!
//! Every renewal opens a row in `renewal` and appends events to
//! `renewal_event` as it walks the CSR / DCV / issuance / install
//! steps. The store is the source of truth the dashboard reads from
//! and the operator can grep when something goes wrong.
//!
//! Connection access is wrapped in `spawn_blocking` so the rest of
//! the daemon (axum, scheduler) stays on the tokio runtime without
//! blocking workers on disk I/O.

mod schema;
mod store;

pub use store::{AuditStore, EventKind, RenewalRecord, RenewalStatus};

#[cfg(test)]
mod tests;
