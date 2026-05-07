use super::*;

#[tokio::test]
async fn opens_clean_in_memory_db() {
  let store = AuditStore::open_in_memory().await.unwrap();
  let latest = store.latest_renewal("anything").await.unwrap();
  assert!(latest.is_none());
}

#[tokio::test]
async fn happy_path_records_renewal_with_events() {
  let store = AuditStore::open_in_memory().await.unwrap();
  let id = store.start_renewal("example-public").await.unwrap();

  for kind in [
    EventKind::CsrGenerated,
    EventKind::CaSubmitted,
    EventKind::DcvPublished,
    EventKind::CertIssued,
    EventKind::CertInstalled,
    EventKind::DcvRemoved,
  ] {
    store.append_event(id, kind, None).await.unwrap();
  }

  store
    .complete_renewal(id, RenewalStatus::Success, None)
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
  assert_eq!(ok, 1);
  assert_eq!(fail, 0);
}

#[tokio::test]
async fn failed_renewal_carries_error_text() {
  let store = AuditStore::open_in_memory().await.unwrap();
  let id = store.start_renewal("flaky").await.unwrap();
  store
    .append_event(id, EventKind::Error, Some("ca returned 500"))
    .await
    .unwrap();
  store
    .complete_renewal(id, RenewalStatus::Failed, Some("ca returned 500"))
    .await
    .unwrap();

  let latest = store.latest_renewal("flaky").await.unwrap().unwrap();
  assert_eq!(latest.status, RenewalStatus::Failed);
  assert_eq!(latest.error.as_deref(), Some("ca returned 500"));

  let (ok, fail) = store.count_by_status("flaky").await.unwrap();
  assert_eq!(ok, 0);
  assert_eq!(fail, 1);
}

#[tokio::test]
async fn latest_renewal_returns_most_recent_of_many() {
  let store = AuditStore::open_in_memory().await.unwrap();
  let first = store.start_renewal("rolling").await.unwrap();
  store
    .complete_renewal(first, RenewalStatus::Success, None)
    .await
    .unwrap();
  let second = store.start_renewal("rolling").await.unwrap();
  store
    .complete_renewal(second, RenewalStatus::Failed, Some("oh no"))
    .await
    .unwrap();

  let latest = store.latest_renewal("rolling").await.unwrap().unwrap();
  assert_eq!(latest.id, second);
  assert_eq!(latest.status, RenewalStatus::Failed);
}

#[tokio::test]
async fn schema_apply_is_idempotent() {
  // Open then drop the store; reopen the same DB and verify nothing
  // breaks. Uses a temp file so both opens see the same disk state.
  let tmp = tempfile::NamedTempFile::new().unwrap();
  let path = tmp.path().to_owned();

  {
    let s = AuditStore::open(&path).await.unwrap();
    s.start_renewal("first-open").await.unwrap();
  }
  let s = AuditStore::open(&path).await.unwrap();
  let latest = s.latest_renewal("first-open").await.unwrap();
  assert!(latest.is_some());
}
