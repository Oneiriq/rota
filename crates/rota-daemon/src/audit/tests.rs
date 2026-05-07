//! Audit store tests.
//!
//! `run_contract` exercises the trait surface end-to-end and is
//! shared across every backend impl. Per-backend modules add tests
//! for impl-specific concerns (file persistence, schema reopening,
//! native id shape, etc.).

use super::*;

/// Cross-backend correctness check. Every `AuditStore` impl must
/// satisfy this; surrealdb tests reuse it via a separate module.
async fn run_contract(store: &dyn AuditStore) {
  // empty cert_id returns no record
  assert!(store.latest_renewal("missing").await.unwrap().is_none());

  // happy path: every step records, terminal status sticks
  let id = store.start_renewal("example-public").await.unwrap();
  for kind in [
    EventKind::CsrGenerated,
    EventKind::CaSubmitted,
    EventKind::DcvPublished,
    EventKind::CertIssued,
    EventKind::CertInstalled,
    EventKind::DcvRemoved,
  ] {
    store.append_event(&id, kind, None).await.unwrap();
  }
  store
    .complete_renewal(&id, RenewalStatus::Success, None)
    .await
    .unwrap();
  let latest = store
    .latest_renewal("example-public")
    .await
    .unwrap()
    .unwrap();
  assert_eq!(latest.id, id);
  assert_eq!(latest.cert_id, "example-public");
  assert_eq!(latest.status, RenewalStatus::Success);
  assert!(latest.error.is_none());
  assert!(latest.completed_at.is_some());
  let (ok, fail) = store.count_by_status("example-public").await.unwrap();
  assert_eq!((ok, fail), (1, 0));

  // failure path: error string round-trips
  let id = store.start_renewal("flaky").await.unwrap();
  store
    .append_event(&id, EventKind::Error, Some("ca returned 500"))
    .await
    .unwrap();
  store
    .complete_renewal(&id, RenewalStatus::Failed, Some("ca returned 500"))
    .await
    .unwrap();
  let latest = store.latest_renewal("flaky").await.unwrap().unwrap();
  assert_eq!(latest.status, RenewalStatus::Failed);
  assert_eq!(latest.error.as_deref(), Some("ca returned 500"));
  let (ok, fail) = store.count_by_status("flaky").await.unwrap();
  assert_eq!((ok, fail), (0, 1));

  // multiple renewals for same cert: latest wins
  let first = store.start_renewal("rolling").await.unwrap();
  store
    .complete_renewal(&first, RenewalStatus::Success, None)
    .await
    .unwrap();
  let second = store.start_renewal("rolling").await.unwrap();
  store
    .complete_renewal(&second, RenewalStatus::Failed, Some("oh no"))
    .await
    .unwrap();
  let latest = store.latest_renewal("rolling").await.unwrap().unwrap();
  assert_eq!(latest.id, second);
  assert_eq!(latest.status, RenewalStatus::Failed);
}

#[tokio::test]
async fn sqlite_satisfies_contract() {
  let store = SqliteAuditStore::open_in_memory().await.unwrap();
  run_contract(&store).await;
  assert_eq!(store.name(), "sqlite");
}

#[tokio::test]
async fn sqlite_schema_apply_is_idempotent_across_reopens() {
  let tmp = tempfile::NamedTempFile::new().unwrap();
  let path = tmp.path().to_owned();
  {
    let s = SqliteAuditStore::open(&path).await.unwrap();
    s.start_renewal("first-open").await.unwrap();
  }
  let s = SqliteAuditStore::open(&path).await.unwrap();
  assert!(s.latest_renewal("first-open").await.unwrap().is_some());
}

#[cfg(feature = "surrealdb")]
#[tokio::test]
async fn surrealdb_satisfies_contract() {
  let store = SurrealAuditStore::open_in_memory().await.unwrap();
  run_contract(&store).await;
  assert_eq!(store.name(), "surrealdb");
}
