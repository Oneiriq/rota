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
use rota_core::backend::{DcvChallenge, RegistrarBackend};
use rota_core::{Error, Result};
use tracing::{debug, info};

use super::client::NamecheapClient;

#[derive(Debug, Clone)]
pub struct NamecheapRegistrar {
  client: Arc<NamecheapClient>,
}

impl NamecheapRegistrar {
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

#[async_trait]
impl RegistrarBackend for NamecheapRegistrar {
  fn name(&self) -> &str {
    "namecheap"
  }

  async fn publish_txt(&self, challenge: &DcvChallenge) -> Result<()> {
    let split = split_record_name(&challenge.record_name)?;
    let mut hosts = self.get_hosts(&split.sld, &split.tld).await?;

    // Idempotent: if the exact (host, value) already exists, no-op.
    if hosts
      .iter()
      .any(|h| h.is_txt() && h.name == split.subdomain && h.address == challenge.record_value)
    {
      debug!(record = %challenge.record_name, "namecheap txt already present");
      return Ok(());
    }

    hosts.push(HostRecord {
      name: split.subdomain,
      record_type: "TXT".to_owned(),
      address: challenge.record_value.clone(),
      mx_pref: "10".to_owned(),
      ttl: challenge.ttl.max(60),
    });

    info!(record = %challenge.record_name, "namecheap publishing dcv txt");
    self.set_hosts(&split.sld, &split.tld, &hosts).await
  }

  async fn remove_txt(&self, challenge: &DcvChallenge) -> Result<()> {
    let split = split_record_name(&challenge.record_name)?;
    let hosts = self.get_hosts(&split.sld, &split.tld).await?;

    let filtered: Vec<HostRecord> = hosts
      .into_iter()
      .filter(|h| !(h.is_txt() && h.name == split.subdomain && h.address == challenge.record_value))
      .collect();

    info!(record = %challenge.record_name, "namecheap removing dcv txt");
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

impl HostRecord {
  fn is_txt(&self) -> bool {
    self.record_type.eq_ignore_ascii_case("TXT")
  }
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
fn split_record_name(record_name: &str) -> Result<SplitName> {
  let parts: Vec<&str> = record_name.trim_end_matches('.').split('.').collect();
  if parts.len() < 2 {
    return Err(Error::Registrar(format!(
      "record name not splittable into sld + tld: {record_name}"
    )));
  }
  let tld = parts[parts.len() - 1].to_owned();
  let sld = parts[parts.len() - 2].to_owned();
  let subdomain = if parts.len() > 2 {
    parts[..parts.len() - 2].join(".")
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
    assert!(hosts[2].is_txt());
  }
}
