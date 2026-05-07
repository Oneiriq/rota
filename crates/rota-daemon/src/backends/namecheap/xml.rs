//! Minimal XML response parsing for Namecheap.
//!
//! The full Namecheap schema is large and inconsistent — different
//! commands return wildly different element trees. Rather than write
//! a strongly-typed deserializer per command, we walk the response
//! tree looking for the few elements each backend needs, and surface
//! parse errors with enough context that a future change in
//! Namecheap's response shape is debuggable from a log line.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rota_core::{Error, Result};

/// Lightweight parsed view of an `<ApiResponse>` envelope.
#[derive(Debug, Clone)]
pub struct ApiResponse {
  /// "OK" or "ERROR".
  pub status: String,
  /// Errors collected from the `<Errors><Error Number=...>...` block,
  /// when status is ERROR.
  pub errors: Vec<ApiError>,
  /// Raw body for callers that need to walk it themselves (parse the
  /// command-specific result block).
  pub raw: String,
}

#[derive(Debug, Clone)]
pub struct ApiError {
  pub number: String,
  pub message: String,
}

impl ApiResponse {
  /// Convert an error response into an [`Error::Ca`] / [`Error::Registrar`]
  /// suitable for surfacing.
  pub fn ensure_ok(&self) -> Result<()> {
    if self.status.eq_ignore_ascii_case("ok") {
      return Ok(());
    }
    let joined = self
      .errors
      .iter()
      .map(|e| format!("{}: {}", e.number, e.message))
      .collect::<Vec<_>>()
      .join("; ");
    Err(Error::Ca(format!("namecheap api error: {joined}")))
  }

  /// Find the first occurrence of an element by name and return its
  /// text content. Convenience for the very common case of pulling a
  /// single value out of a response (e.g. `<HttpDCValidation>` host
  /// name + value).
  pub fn first_text(&self, element: &str) -> Option<String> {
    let mut reader = Reader::from_str(&self.raw);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut inside = false;
    loop {
      match reader.read_event_into(&mut buf) {
        Ok(Event::Start(e)) => {
          if e.local_name().as_ref() == element.as_bytes() {
            inside = true;
          }
        }
        Ok(Event::Text(e)) if inside => {
          return Some(e.unescape().ok()?.into_owned());
        }
        Ok(Event::End(e)) if e.local_name().as_ref() == element.as_bytes() => {
          inside = false;
        }
        Ok(Event::Eof) | Err(_) => return None,
        _ => {}
      }
      buf.clear();
    }
  }

  /// Find the first occurrence of an element by name and return one
  /// of its attribute values.
  pub fn first_attribute(&self, element: &str, attr: &str) -> Option<String> {
    let mut reader = Reader::from_str(&self.raw);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    loop {
      match reader.read_event_into(&mut buf) {
        Ok(Event::Start(e) | Event::Empty(e)) => {
          if e.local_name().as_ref() == element.as_bytes() {
            for a in e.attributes().flatten() {
              if a.key.as_ref() == attr.as_bytes() {
                return String::from_utf8(a.value.into_owned()).ok();
              }
            }
          }
        }
        Ok(Event::Eof) | Err(_) => return None,
        _ => {}
      }
      buf.clear();
    }
  }
}

pub(super) fn parse_response(body: &str) -> Result<ApiResponse> {
  let mut reader = Reader::from_str(body);
  reader.config_mut().trim_text(true);

  let mut status = None;
  let mut errors = Vec::new();
  let mut buf = Vec::new();
  let mut current_error_number: Option<String> = None;
  let mut in_error = false;
  let mut error_text = String::new();

  loop {
    match reader.read_event_into(&mut buf) {
      Ok(Event::Start(e) | Event::Empty(e)) => {
        let name = e.local_name();
        let name_bytes = name.as_ref();
        if name_bytes == b"ApiResponse" {
          for attr in e.attributes().flatten() {
            if attr.key.as_ref() == b"Status" {
              status = String::from_utf8(attr.value.into_owned()).ok();
            }
          }
        } else if name_bytes == b"Error" {
          in_error = true;
          error_text.clear();
          current_error_number = e
            .attributes()
            .flatten()
            .find(|a| a.key.as_ref() == b"Number")
            .and_then(|a| String::from_utf8(a.value.into_owned()).ok());
        }
      }
      Ok(Event::Text(e)) if in_error => {
        if let Ok(s) = e.unescape() {
          error_text.push_str(&s);
        }
      }
      Ok(Event::End(e)) => {
        if e.local_name().as_ref() == b"Error" {
          errors.push(ApiError {
            number: current_error_number.take().unwrap_or_default(),
            message: error_text.trim().to_owned(),
          });
          in_error = false;
        }
      }
      Ok(Event::Eof) => break,
      Err(err) => {
        return Err(Error::Ca(format!("namecheap xml parse: {err}")));
      }
      _ => {}
    }
    buf.clear();
  }

  Ok(ApiResponse {
    status: status.unwrap_or_else(|| "UNKNOWN".to_owned()),
    errors,
    raw: body.to_owned(),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_ok_envelope() {
    let body = r#"<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <CommandResponse Type="namecheap.ssl.reissue">
    <SSLReissueResult IsSuccess="true" CertificateID="12345678"/>
  </CommandResponse>
</ApiResponse>"#;
    let resp = parse_response(body).unwrap();
    assert_eq!(resp.status, "OK");
    assert!(resp.errors.is_empty());
    assert_eq!(
      resp
        .first_attribute("SSLReissueResult", "IsSuccess")
        .as_deref(),
      Some("true")
    );
  }

  #[test]
  fn parses_error_envelope() {
    let body = r#"<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR">
  <Errors>
    <Error Number="1010101">Authentication failed</Error>
  </Errors>
</ApiResponse>"#;
    let resp = parse_response(body).unwrap();
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.errors.len(), 1);
    assert_eq!(resp.errors[0].number, "1010101");
    assert!(resp.errors[0].message.contains("Authentication failed"));
    assert!(resp.ensure_ok().is_err());
  }
}
