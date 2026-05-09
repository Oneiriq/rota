//! Two responsibilities, both about secrets in config + logs:
//!
//! 1. [`redact`]: best-effort scrubbing of secret-shaped substrings
//!    in error strings and log messages.
//! 2. [`read_secret`] + [`expand_env`]: env-var resolution at
//!    config-load time, so operators can drive rota.yaml from a
//!    secret manager (Doppler, Vault agent, etc.) without writing
//!    plaintext files to disk. `*_file:` paths accept an `env:NAME`
//!    sentinel and `String` fields accept `${VAR}` interpolation.

use std::path::Path;

use crate::{Error, Result};

/// Path-prefix sentinel for env-var-driven secrets. A `*_file:` field
/// set to e.g. `env:NAMECHEAP_API_KEY` reads the named environment
/// variable instead of opening a file.
const ENV_PREFIX: &str = "env:";

/// Read a secret. If `path` is `env:NAME`, returns the value of the
/// named env var; otherwise reads the file at `path`. Trims trailing
/// whitespace so a key file with a stray newline still produces the
/// raw secret. Errors classify as [`Error::ConfigInvalid`] either way.
pub fn read_secret(path: &Path) -> Result<String> {
  if let Some(name) = env_ref(path) {
    return read_env(&name);
  }
  let raw = std::fs::read_to_string(path)
    .map_err(|e| Error::ConfigInvalid(format!("secret file {}: {e}", path.display())))?;
  Ok(raw.trim().to_owned())
}

/// Expand `${VAR}` references in `s` against the process environment.
/// Multiple references in one string are supported; literal `$` outside
/// `${...}` passes through unchanged. An unset variable or an
/// unterminated `${...}` returns [`Error::ConfigInvalid`].
pub fn expand_env(s: &str) -> Result<String> {
  if !s.contains("${") {
    return Ok(s.to_owned());
  }
  let mut out = String::with_capacity(s.len());
  let mut rest = s;
  while let Some(i) = rest.find("${") {
    out.push_str(&rest[..i]);
    let after = &rest[i + 2..];
    let end = after.find('}').ok_or_else(|| {
      Error::ConfigInvalid(format!("unterminated ${{...}} in config string {s:?}"))
    })?;
    let var = &after[..end];
    out.push_str(&read_env(var)?);
    rest = &after[end + 1..];
  }
  out.push_str(rest);
  Ok(out)
}

fn env_ref(path: &Path) -> Option<String> {
  path
    .to_str()
    .and_then(|s| s.strip_prefix(ENV_PREFIX))
    .map(|s| s.trim().to_owned())
}

fn read_env(name: &str) -> Result<String> {
  std::env::var(name).map_err(|_| {
    Error::ConfigInvalid(format!(
      "env var {name} is referenced in config but not set in the process environment"
    ))
  })
}

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

  // env-var resolution

  use std::path::PathBuf;

  #[test]
  fn read_secret_from_file_trims_whitespace() {
    let mut path = std::env::temp_dir();
    path.push(format!("rota-secret-{}.txt", std::process::id()));
    std::fs::write(&path, "abc123\n").unwrap();
    assert_eq!(read_secret(&path).unwrap(), "abc123");
    std::fs::remove_file(&path).ok();
  }

  #[test]
  fn read_secret_resolves_env_prefix() {
    std::env::set_var("ROTA_TEST_SECRET_RESOLVE", "from-env-resolved");
    let path = PathBuf::from("env:ROTA_TEST_SECRET_RESOLVE");
    assert_eq!(read_secret(&path).unwrap(), "from-env-resolved");
    std::env::remove_var("ROTA_TEST_SECRET_RESOLVE");
  }

  #[test]
  fn read_secret_errors_when_env_var_unset() {
    let path = PathBuf::from("env:ROTA_TEST_SECRET_DEFINITELY_UNSET");
    let err = read_secret(&path).unwrap_err();
    assert!(err
      .to_string()
      .contains("ROTA_TEST_SECRET_DEFINITELY_UNSET"));
  }

  #[test]
  fn expand_env_passthrough_when_no_braces() {
    assert_eq!(expand_env("plain string").unwrap(), "plain string");
    assert_eq!(expand_env("").unwrap(), "");
  }

  #[test]
  fn expand_env_substitutes_single_var() {
    std::env::set_var("ROTA_TEST_EXPAND_USER", "alice");
    assert_eq!(expand_env("${ROTA_TEST_EXPAND_USER}").unwrap(), "alice");
    assert_eq!(
      expand_env("hi-${ROTA_TEST_EXPAND_USER}!").unwrap(),
      "hi-alice!"
    );
    std::env::remove_var("ROTA_TEST_EXPAND_USER");
  }

  #[test]
  fn expand_env_substitutes_multiple_vars() {
    std::env::set_var("ROTA_TEST_EXPAND_A", "1");
    std::env::set_var("ROTA_TEST_EXPAND_B", "2");
    assert_eq!(
      expand_env("${ROTA_TEST_EXPAND_A}-${ROTA_TEST_EXPAND_B}").unwrap(),
      "1-2"
    );
    std::env::remove_var("ROTA_TEST_EXPAND_A");
    std::env::remove_var("ROTA_TEST_EXPAND_B");
  }

  #[test]
  fn expand_env_errors_on_unset_var() {
    let err = expand_env("${ROTA_TEST_EXPAND_DEFINITELY_UNSET}").unwrap_err();
    assert!(err
      .to_string()
      .contains("ROTA_TEST_EXPAND_DEFINITELY_UNSET"));
  }

  #[test]
  fn expand_env_errors_on_unterminated_brace() {
    assert!(expand_env("${ROTA_TEST_EXPAND_UNTERMINATED").is_err());
  }
}
