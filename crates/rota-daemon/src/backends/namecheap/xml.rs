//! Minimal XML response parsing for Namecheap.
//!
//! The full Namecheap schema is large and inconsistent; different
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
        // Namecheap wraps DCV record values in `<![CDATA[...]]>` so
        // operator-supplied values (DNS labels with dots, URLs, etc.)
        // pass through unescaped. quick-xml fires Event::CData for
        // these, not Event::Text. Handling both keeps the helper
        // robust to either encoding.
        Ok(Event::CData(e)) if inside => {
          return String::from_utf8(e.into_inner().into_owned()).ok();
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

  /// Find every PEM block of the given label (e.g. `"CERTIFICATE"`)
  /// in the raw response and return them in document order.
  ///
  /// Cuts through Namecheap's nested-element wrapping for cert
  /// payloads: `namecheap.ssl.getInfo&Returncertificate=true` packs
  /// the leaf as `<Certificates><Certificate><![CDATA[PEM]]></Certificate>`
  /// and EACH chain cert under
  /// `<Certificates><CaCertificates><Certificate Type="INTERMEDIATE">
  ///    <Certificate><![CDATA[PEM]]></Certificate></Certificate></CaCertificates>`,
  /// which `first_text` can't disambiguate by element name alone.
  /// Scanning for the literal PEM armor avoids walking that mess.
  ///
  /// `BEGIN CERTIFICATE-----` does NOT match `BEGIN CERTIFICATE REQUEST-----`
  /// (the trailing `-----` differs), so a CSR present in the same
  /// response is safely skipped when querying for `"CERTIFICATE"`.
  pub fn pem_blocks(&self, label: &str) -> Vec<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = self.raw.as_str();
    while let Some(b) = rest.find(&begin) {
      let after_begin = &rest[b..];
      let Some(e) = after_begin.find(&end) else {
        break;
      };
      let block_end = e + end.len();
      out.push(after_begin[..block_end].to_owned());
      rest = &after_begin[block_end..];
    }
    out
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
  fn first_text_unwraps_cdata() {
    // Namecheap's actual reissue response wraps the DCV CNAME values
    // in CDATA blocks. quick-xml fires Event::CData for these, not
    // Event::Text, so the parser must handle both.
    let body = r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
  <CommandResponse>
    <SSLReissueResult ID="34351741" IsSuccess="true">
      <DNSDCValidation ValueAvailable="true">
        <DNS domain="oneiric.dev">
          <HostName><![CDATA[_6958EA56A4FE23DDF2C3EDA7B9B956A5.oneiric.dev]]></HostName>
          <Target><![CDATA[46513AD29B078AF908AD3CDF354A8599.6CD5AE645BCCE1FAA847D98385AFF6CE.69ff68dc5168c.comodoca.com]]></Target>
        </DNS>
      </DNSDCValidation>
    </SSLReissueResult>
  </CommandResponse>
</ApiResponse>"#;
    let resp = parse_response(body).unwrap();
    assert_eq!(
      resp.first_text("HostName").as_deref(),
      Some("_6958EA56A4FE23DDF2C3EDA7B9B956A5.oneiric.dev")
    );
    assert_eq!(
      resp.first_text("Target").as_deref(),
      Some("46513AD29B078AF908AD3CDF354A8599.6CD5AE645BCCE1FAA847D98385AFF6CE.69ff68dc5168c.comodoca.com")
    );
  }

  #[test]
  fn pem_blocks_extracts_leaf_plus_chain_in_document_order() {
    let body = r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
 <CommandResponse>
  <SSLGetInfoResult Status="active">
   <CertificateDetails>
    <CSR><![CDATA[-----BEGIN CERTIFICATE REQUEST-----
CSR_BODY
-----END CERTIFICATE REQUEST-----]]></CSR>
    <Certificates CertificateReturned="true" ReturnType="INDIVIDUAL">
     <Certificate><![CDATA[-----BEGIN CERTIFICATE-----
LEAF_BODY
-----END CERTIFICATE-----]]></Certificate>
     <CaCertificates>
      <Certificate Type="INTERMEDIATE">
       <Certificate><![CDATA[-----BEGIN CERTIFICATE-----
INT1_BODY
-----END CERTIFICATE-----]]></Certificate>
      </Certificate>
      <Certificate Type="INTERMEDIATE">
       <Certificate><![CDATA[-----BEGIN CERTIFICATE-----
INT2_BODY
-----END CERTIFICATE-----]]></Certificate>
      </Certificate>
     </CaCertificates>
    </Certificates>
   </CertificateDetails>
  </SSLGetInfoResult>
 </CommandResponse>
</ApiResponse>"#;
    let resp = parse_response(body).unwrap();
    let blocks = resp.pem_blocks("CERTIFICATE");
    assert_eq!(blocks.len(), 3, "leaf + 2 intermediates, CSR skipped");
    assert!(blocks[0].contains("LEAF_BODY"), "first block is the leaf");
    assert!(
      blocks[1].contains("INT1_BODY"),
      "second block is intermediate 1"
    );
    assert!(
      blocks[2].contains("INT2_BODY"),
      "third block is intermediate 2"
    );
    // CSR has the CERTIFICATE REQUEST label and must NOT be picked up
    // when querying for the CERTIFICATE label.
    assert!(!blocks.iter().any(|b| b.contains("CSR_BODY")));
  }

  #[test]
  fn pem_blocks_does_not_match_csr_label() {
    let body = r#"<?xml version="1.0"?>
<root>
  <CSR><![CDATA[-----BEGIN CERTIFICATE REQUEST-----
ABCD
-----END CERTIFICATE REQUEST-----]]></CSR>
</root>"#;
    let resp = parse_response(body).unwrap();
    let blocks = resp.pem_blocks("CERTIFICATE");
    assert!(
      blocks.is_empty(),
      "BEGIN CERTIFICATE----- has trailing dashes immediately after CERTIFICATE; BEGIN CERTIFICATE REQUEST----- does not match"
    );
  }

  #[test]
  fn pem_blocks_returns_empty_when_no_match() {
    let resp = parse_response("<root></root>").unwrap();
    assert!(resp.pem_blocks("CERTIFICATE").is_empty());
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
