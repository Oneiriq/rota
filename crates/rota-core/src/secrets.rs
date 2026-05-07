//! Best-effort redaction of secrets that show up in error strings
//! and log messages.
//!
//! Use this any time a string that may have come from an HTTP error,
//! a vendor SDK, or a wrapped error chain is about to land in a log
//! line, an audit row, or a user-facing error message. The Namecheap
//! API in particular carries auth in URL query params (`ApiKey=...`),
//! and `reqwest::Error`'s Debug impl embeds the request URL, so any
//! error originating from a network call may surface the key
//! verbatim. The function is best-effort: it strips the patterns we
//! know about, and we add patterns as we find them. Non-matching
//! input passes through unchanged.

const PATTERNS: &[&str] = &[
  // Namecheap API auth.
  "ApiKey=",
  "ApiUser=",
  // Generic forms.
  "api_key=",
  "api-key=",
  "apikey=",
  "password=",
  "passwd=",
  "token=",
  "secret=",
  // Authorization headers when serialized as text.
  "Bearer ",
];

/// Scrub known secret patterns from `s`. The match is
/// case-insensitive on the prefix; the value (everything up to `&`,
/// whitespace, or end-of-string) is replaced with `<redacted>`.
pub fn redact(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  let bytes = s.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    let mut matched = false;
    for pat in PATTERNS {
      let pb = pat.as_bytes();
      if i + pb.len() <= bytes.len() && bytes[i..i + pb.len()].eq_ignore_ascii_case(pb) {
        out.push_str(pat);
        out.push_str("<redacted>");
        i += pb.len();
        // Skip until value terminator: `&`, whitespace, or `"`.
        while i < bytes.len() && !is_value_terminator(bytes[i]) {
          i += 1;
        }
        matched = true;
        break;
      }
    }
    if !matched {
      out.push(bytes[i] as char);
      i += 1;
    }
  }
  out
}

fn is_value_terminator(b: u8) -> bool {
  matches!(b, b'&' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'')
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn redacts_namecheap_url_query() {
    let url = "https://api.namecheap.com/xml.response?ApiUser=alice&ApiKey=deadbeefcafef00d&Command=ssl.list";
    let redacted = redact(url);
    assert!(redacted.contains("ApiUser=<redacted>"));
    assert!(redacted.contains("ApiKey=<redacted>"));
    assert!(redacted.contains("Command=ssl.list"));
    assert!(!redacted.contains("deadbeefcafef00d"));
    assert!(!redacted.contains("alice"));
  }

  #[test]
  fn redacts_inside_reqwest_error_debug_repr() {
    let s = r#"Error { kind: Connect, url: "https://api.namecheap.com/xml.response?ApiKey=secret123&Command=ssl.getInfo", source: ... }"#;
    let r = redact(s);
    assert!(!r.contains("secret123"));
    assert!(r.contains("ApiKey=<redacted>"));
    assert!(r.contains("Command=ssl.getInfo"));
  }

  #[test]
  fn redacts_bearer_token_in_authorization_header() {
    let s = "Authorization: Bearer ey.JhbG.ciOiJIU";
    let r = redact(s);
    assert!(!r.contains("ey.JhbG"));
    assert!(r.contains("Bearer <redacted>"));
  }

  #[test]
  fn case_insensitive_prefix_match() {
    assert!(redact("APIKEY=foo").contains("<redacted>"));
    assert!(redact("api_key=foo").contains("<redacted>"));
    assert!(redact("Api-Key=foo").contains("<redacted>"));
  }

  #[test]
  fn passes_through_strings_with_no_secrets() {
    let s = "regular log line cert=example-public renewal_id=42";
    assert_eq!(redact(s), s);
  }

  #[test]
  fn handles_value_terminators_correctly() {
    assert_eq!(
      redact("ApiKey=abc def"),
      "ApiKey=<redacted> def",
      "space terminates the value"
    );
    assert_eq!(
      redact("ApiKey=abc&Other=val"),
      "ApiKey=<redacted>&Other=val",
      "ampersand terminates the value"
    );
    assert_eq!(
      redact(r#"{"ApiKey":"abc"}"#),
      r#"{"ApiKey":"abc"}"#,
      "JSON quoted form is not in the patterns table; safe pass-through"
    );
  }

  #[test]
  fn empty_string_is_empty() {
    assert_eq!(redact(""), "");
  }
}
