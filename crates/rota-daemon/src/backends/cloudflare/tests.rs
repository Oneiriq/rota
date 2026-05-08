use super::*;

#[test]
fn zone_candidates_walks_labels_apex_only() {
  assert_eq!(zone_candidates("example.com"), vec!["example.com"]);
}

#[test]
fn zone_candidates_walks_labels_three_label() {
  assert_eq!(
    zone_candidates("_acme-challenge.example.com"),
    vec!["_acme-challenge.example.com", "example.com"]
  );
}

#[test]
fn zone_candidates_walks_labels_deep_subdomain() {
  assert_eq!(
    zone_candidates("_acme-challenge.api.dashboard.example.com"),
    vec![
      "_acme-challenge.api.dashboard.example.com",
      "api.dashboard.example.com",
      "dashboard.example.com",
      "example.com",
    ]
  );
}

#[test]
fn zone_candidates_strips_trailing_dot() {
  assert_eq!(zone_candidates("example.com."), vec!["example.com"]);
}

#[test]
fn api_response_parses_ok_envelope_with_result() {
  let body = r#"{
    "success": true,
    "errors": [],
    "result": [{"id": "abc123"}]
  }"#;
  let parsed: ApiResponse<Vec<Zone>> = serde_json::from_str(body).unwrap();
  assert!(parsed.success);
  let zones = parsed.result.unwrap();
  assert_eq!(zones.len(), 1);
  assert_eq!(zones[0].id, "abc123");
}

#[test]
fn api_response_parses_error_envelope() {
  let body = r#"{
    "success": false,
    "errors": [{"code": 6003, "message": "Invalid request headers"}],
    "result": null
  }"#;
  let parsed: ApiResponse<Vec<Zone>> = serde_json::from_str(body).unwrap();
  assert!(!parsed.success);
  assert_eq!(parsed.errors.len(), 1);
  assert_eq!(parsed.errors[0].code, 6003);
}

#[test]
fn dns_record_deserialise_handles_quoted_content() {
  let body = r#"{
    "success": true,
    "errors": [],
    "result": [{"id": "rec1", "content": "\"deadbeef\""}]
  }"#;
  let parsed: ApiResponse<Vec<DnsRecord>> = serde_json::from_str(body).unwrap();
  let records = parsed.result.unwrap();
  // Cloudflare returns TXT content wrapped in quotes; the registrar
  // strips them when comparing for idempotency.
  assert_eq!(records[0].content, "\"deadbeef\"");
  assert_eq!(records[0].content.trim_matches('"'), "deadbeef");
}

#[test]
fn debug_repr_redacts_api_token() {
  let client = CloudflareClient::new("topsecret-cf-token-abc123".to_owned());
  let s = format!("{client:?}");
  assert!(s.contains("<redacted>"));
  assert!(!s.contains("topsecret-cf-token-abc123"));
}
