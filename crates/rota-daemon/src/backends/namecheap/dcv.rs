//! `namecheap.domains.dns.{getHosts,setHosts}` for DNS-01 DCV.
//!
//! Critical Namecheap-DNS gotcha: `setHosts` is a **full replacement**
//! of every record on the domain, not a per-record edit. Publishing
//! one TXT therefore requires reading every existing record first,
//! merging the new one in, and writing the merged set back. Same
//! pattern in reverse for removal. Skipping the read step would wipe
//! every other record on the domain.

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rota_core::backend::{ChallengeKind, DcvBackend, DcvChallenge};
use rota_core::{Error, Result};
use tracing::{debug, info};

use super::client::NamecheapClient;

#[derive(Debug, Clone)]
pub struct NamecheapDcv {
  client: Arc<NamecheapClient>,
}

impl NamecheapDcv {
  pub fn new(client: Arc<NamecheapClient>) -> Self {
    Self { client }
  }

  /// Pull every host record on a domain. Returns the merged-set
  /// payload Namecheap expects on `setHosts`.
  async fn get_hosts(&self, sld: &str, tld: &str) -> Result<Vec<HostRecord>> {
    let resp = self
      .client
      .call(
        "namecheap.domains.dns.getHosts",
        [("SLD", sld.to_owned()), ("TLD", tld.to_owned())],
      )
      .await?;
    resp.ensure_ok()?;
    Ok(parse_hosts(&resp.raw))
  }

  /// Replace the full host record set. Caller owns merging.
  async fn set_hosts(&self, sld: &str, tld: &str, hosts: &[HostRecord]) -> Result<()> {
    let mut params: Vec<(&'static str, String)> =
      vec![("SLD", sld.to_owned()), ("TLD", tld.to_owned())];
    for (idx, host) in hosts.iter().enumerate() {
      let n = idx + 1;
      params.push((leak(format!("HostName{n}")), host.name.clone()));
      params.push((leak(format!("RecordType{n}")), host.record_type.clone()));
      params.push((leak(format!("Address{n}")), host.address.clone()));
      params.push((leak(format!("MXPref{n}")), host.mx_pref.clone()));
      params.push((leak(format!("TTL{n}")), host.ttl.to_string()));
    }
    let resp = self
      .client
      .call("namecheap.domains.dns.setHosts", params)
      .await?;
    resp.ensure_ok()
  }
}

const SUPPORTED: &[ChallengeKind] = &[ChallengeKind::Dns01, ChallengeKind::DnsCname];

/// Parts of a `DcvChallenge` rota's namecheap DCV cares about,
/// independent of the DNS record type. Pulling these out lets
/// `publish` and `remove` share the get-merge-set dance regardless
/// of TXT vs CNAME.
struct ChallengeParts<'a> {
  record_name: &'a str,
  record_value: &'a str,
  ttl: u32,
  record_type: &'static str,
}

fn challenge_parts(challenge: &DcvChallenge) -> Result<ChallengeParts<'_>> {
  match challenge {
    DcvChallenge::Dns01 {
      record_name,
      record_value,
      ttl,
    } => Ok(ChallengeParts {
      record_name,
      record_value,
      ttl: *ttl,
      record_type: "TXT",
    }),
    DcvChallenge::DnsCname {
      record_name,
      record_value,
      ttl,
    } => Ok(ChallengeParts {
      record_name,
      record_value,
      ttl: *ttl,
      record_type: "CNAME",
    }),
    _ => Err(Error::Registrar(format!(
      "namecheap dcv only supports dns-01 and dns-cname, got {}",
      challenge.kind_str()
    ))),
  }
}

#[async_trait]
impl DcvBackend for NamecheapDcv {
  fn name(&self) -> &str {
    "namecheap"
  }

  fn supported_kinds(&self) -> &[ChallengeKind] {
    SUPPORTED
  }

  async fn publish(&self, challenge: &DcvChallenge) -> Result<()> {
    let parts = challenge_parts(challenge)?;
    let split = split_record_name(parts.record_name)?;
    let mut hosts = self.get_hosts(&split.sld, &split.tld).await?;

    // Idempotent: if the exact (type, host, value) already exists, no-op.
    if hosts.iter().any(|h| {
      h.record_type.eq_ignore_ascii_case(parts.record_type)
        && h.name == split.subdomain
        && h.address == parts.record_value
    }) {
      debug!(record = %parts.record_name, kind = %challenge.kind_str(), "namecheap dcv record already present");
      return Ok(());
    }

    hosts.push(HostRecord {
      name: split.subdomain,
      record_type: parts.record_type.to_owned(),
      address: parts.record_value.to_owned(),
      mx_pref: "10".to_owned(),
      ttl: parts.ttl.max(60),
    });

    info!(record = %parts.record_name, kind = %challenge.kind_str(), "namecheap publishing dcv record");
    self.set_hosts(&split.sld, &split.tld, &hosts).await
  }

  async fn remove(&self, challenge: &DcvChallenge) -> Result<()> {
    let parts = challenge_parts(challenge)?;
    let split = split_record_name(parts.record_name)?;
    let hosts = self.get_hosts(&split.sld, &split.tld).await?;

    let filtered: Vec<HostRecord> = hosts
      .into_iter()
      .filter(|h| {
        !(h.record_type.eq_ignore_ascii_case(parts.record_type)
          && h.name == split.subdomain
          && h.address == parts.record_value)
      })
      .collect();

    info!(record = %parts.record_name, kind = %challenge.kind_str(), "namecheap removing dcv record");
    self.set_hosts(&split.sld, &split.tld, &filtered).await
  }
}

#[derive(Debug, Clone)]
struct HostRecord {
  name: String,
  record_type: String,
  address: String,
  mx_pref: String,
  ttl: u32,
}

#[derive(Debug, Clone)]
struct SplitName {
  subdomain: String,
  sld: String,
  tld: String,
}

/// Split `_acme-challenge.example.com` into
/// `(subdomain="_acme-challenge", sld="example", tld="com")`. The
/// Namecheap DNS API addresses domains as separate SLD + TLD parts.
///
/// The subdomain is lowercased: Namecheap's `domains.dns.setHosts`
/// validates HostName case-sensitively and rejects uppercase letters
/// with `2050900: INVALID_NAME` — even though DNS itself is
/// case-insensitive at resolution time. Sectigo's CSR-hash CNAME
/// response delivers an uppercase MD5 hex (e.g. `_6958EA56...`);
/// without normalization rota's setHosts call dies before the record
/// is published. Sectigo's validator does a case-insensitive lookup
/// so the lowercased CNAME still resolves correctly.
fn split_record_name(record_name: &str) -> Result<SplitName> {
  let parts: Vec<&str> = record_name.trim_end_matches('.').split('.').collect();
  if parts.len() < 2 {
    return Err(Error::Registrar(format!(
      "record name not splittable into sld + tld: {record_name}"
    )));
  }
  let tld = parts[parts.len() - 1].to_ascii_lowercase();
  let sld = parts[parts.len() - 2].to_ascii_lowercase();
  let subdomain = if parts.len() > 2 {
    parts[..parts.len() - 2].join(".").to_ascii_lowercase()
  } else {
    "@".to_owned()
  };
  Ok(SplitName {
    subdomain,
    sld,
    tld,
  })
}

fn parse_hosts(body: &str) -> Vec<HostRecord> {
  let mut reader = Reader::from_str(body);
  reader.config_mut().trim_text(true);
  let mut buf = Vec::new();
  let mut hosts = Vec::new();
  loop {
    match reader.read_event_into(&mut buf) {
      Ok(Event::Empty(e) | Event::Start(e)) => {
        if e.local_name().as_ref() == b"host" {
          let mut name = None;
          let mut record_type = None;
          let mut address = None;
          let mut mx_pref = "10".to_owned();
          let mut ttl: u32 = 1800;
          for attr in e.attributes().flatten() {
            let value = String::from_utf8_lossy(&attr.value).into_owned();
            match attr.key.as_ref() {
              b"Name" => name = Some(value),
              b"Type" => record_type = Some(value),
              b"Address" => address = Some(value),
              b"MXPref" => mx_pref = value,
              b"TTL" => ttl = value.parse().unwrap_or(1800),
              _ => {}
            }
          }
          if let (Some(name), Some(record_type), Some(address)) = (name, record_type, address) {
            hosts.push(HostRecord {
              name,
              record_type,
              address,
              mx_pref,
              ttl,
            });
          }
        }
      }
      Ok(Event::Eof) | Err(_) => break,
      _ => {}
    }
    buf.clear();
  }
  hosts
}

/// Leak a `String` into `'static` so it can be used as a query-param
/// key. Acceptable here because the number of params per setHosts
/// call is bounded by the number of records on a domain (small) and
/// rota is a long-running daemon where a few KB of leaked strings
/// per renewal is invisible.
fn leak(s: String) -> &'static str {
  Box::leak(s.into_boxed_str())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn splits_three_label_record() {
    let s = split_record_name("_acme-challenge.example.com").unwrap();
    assert_eq!(s.subdomain, "_acme-challenge");
    assert_eq!(s.sld, "example");
    assert_eq!(s.tld, "com");
  }

  #[test]
  fn lowercases_uppercase_subdomain_for_namecheap_compat() {
    // Sectigo's CSR-hash CNAME response delivers an uppercase MD5;
    // Namecheap's setHosts rejects uppercase HostNames with 2050900.
    // split_record_name normalizes to lowercase so the publish path
    // doesn't blow up. DNS resolution is case-insensitive so this
    // doesn't break Sectigo's validator.
    let s = split_record_name("_6958EA56A4FE23DDF2C3EDA7B9B956A5.Oneiric.Dev").unwrap();
    assert_eq!(s.subdomain, "_6958ea56a4fe23ddf2c3eda7b9b956a5");
    assert_eq!(s.sld, "oneiric");
    assert_eq!(s.tld, "dev");
  }

  #[test]
  fn splits_apex_only() {
    let s = split_record_name("example.com").unwrap();
    assert_eq!(s.subdomain, "@");
    assert_eq!(s.sld, "example");
    assert_eq!(s.tld, "com");
  }

  #[test]
  fn splits_nested_subdomain() {
    let s = split_record_name("_acme-challenge.api.dashboard.example.com").unwrap();
    assert_eq!(s.subdomain, "_acme-challenge.api.dashboard");
    assert_eq!(s.sld, "example");
    assert_eq!(s.tld, "com");
  }

  #[test]
  fn parses_hosts_response() {
    let body = r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
  <CommandResponse>
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
      <host HostId="1" Name="@" Type="A" Address="66.223.140.2" MXPref="10" TTL="1800"/>
      <host HostId="2" Name="www" Type="CNAME" Address="example.com." MXPref="10" TTL="1800"/>
      <host HostId="3" Name="_existing" Type="TXT" Address="abc123" MXPref="10" TTL="60"/>
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>"#;
    let hosts = parse_hosts(body);
    assert_eq!(hosts.len(), 3);
    assert_eq!(hosts[0].name, "@");
    assert_eq!(hosts[1].record_type, "CNAME");
    assert!(hosts[2].record_type.eq_ignore_ascii_case("TXT"));
  }
}
