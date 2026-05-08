//! Pretty-print helpers for the CLI subcommands.
//!
//! Lightweight column formatting for the small tables `rota status`
//! and `rota log` produce. No external dep; the data shape is tiny
//! (one row per configured cert, a handful of log entries) so a
//! manual padding pass is cheaper than pulling a tables crate.

use chrono::{DateTime, Utc};
use rota_core::protocol::{CertSummary, LogEntry};

/// Render a `Status` response as a table. Returns the formatted
/// string so callers can route it to stdout or compare in tests.
pub fn render_status(certs: &[CertSummary]) -> String {
  if certs.is_empty() {
    return "no certs configured\n".to_owned();
  }

  let headers = ["ID", "DOMAINS", "DAYS LEFT", "LAST RENEWAL", "STATUS"];
  let rows: Vec<[String; 5]> = certs
    .iter()
    .map(|c| {
      [
        c.id.clone(),
        c.domains.join(", "),
        c.days_until_expiry
          .map(|d| d.to_string())
          .unwrap_or_else(|| "-".to_owned()),
        c.last_renewal_at
          .as_ref()
          .map(format_ts)
          .unwrap_or_else(|| "-".to_owned()),
        c.last_renewal_status
          .clone()
          .unwrap_or_else(|| "-".to_owned()),
      ]
    })
    .collect();

  render_table(&headers, &rows)
}

/// Render a `Log` response (latest renewal, possibly empty) as a
/// short prose summary. The full pageable history table lands once
/// `AuditStore::list_renewals` exists.
pub fn render_log(cert_id: &str, events: &[LogEntry]) -> String {
  if events.is_empty() {
    return format!("no renewals recorded for {cert_id}\n");
  }
  let mut out = String::new();
  for ev in events {
    out.push_str(&format!(
      "renewal {} for {cert_id}\n  started:   {}\n  completed: {}\n  status:    {}\n",
      ev.renewal_id,
      format_ts(&ev.started_at),
      ev.completed_at
        .as_ref()
        .map(format_ts)
        .unwrap_or_else(|| "in progress".to_owned()),
      ev.status,
    ));
    if let Some(err) = &ev.error {
      out.push_str(&format!("  error:     {err}\n"));
    }
  }
  out
}

fn render_table(headers: &[&str], rows: &[[String; 5]]) -> String {
  let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
  for row in rows {
    for (i, cell) in row.iter().enumerate() {
      widths[i] = widths[i].max(cell.len());
    }
  }
  let mut out = String::new();
  for (i, h) in headers.iter().enumerate() {
    if i > 0 {
      out.push_str("  ");
    }
    out.push_str(&pad(h, widths[i]));
  }
  out.push('\n');
  for row in rows {
    for (i, cell) in row.iter().enumerate() {
      if i > 0 {
        out.push_str("  ");
      }
      out.push_str(&pad(cell, widths[i]));
    }
    out.push('\n');
  }
  out
}

fn pad(s: &str, width: usize) -> String {
  if s.len() >= width {
    s.to_owned()
  } else {
    format!("{}{}", s, " ".repeat(width - s.len()))
  }
}

fn format_ts(t: &DateTime<Utc>) -> String {
  t.format("%Y-%m-%d %H:%MZ").to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_cert(id: &str, days: Option<i64>, status: Option<&str>) -> CertSummary {
    CertSummary {
      id: id.to_owned(),
      description: String::new(),
      domains: vec!["example.com".to_owned(), "www.example.com".to_owned()],
      ca_backend: "namecheap".to_owned(),
      dcv_backend: "namecheap".to_owned(),
      install_backend: Some("filesystem".to_owned()),
      not_after: None,
      days_until_expiry: days,
      last_renewal_at: None,
      last_renewal_status: status.map(str::to_owned),
      last_renewal_error: None,
    }
  }

  #[test]
  fn render_status_empty_says_so() {
    assert_eq!(render_status(&[]), "no certs configured\n");
  }

  #[test]
  fn render_status_columns_align() {
    let certs = vec![
      sample_cert("alpha", Some(15), Some("success")),
      sample_cert("beta-very-long-id", None, None),
    ];
    let table = render_status(&certs);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("ID"));
    // "beta-very-long-id" pushes the column wider than the header
    // "ID"; both data lines should respect that width and the
    // second column should start at the same offset on every line.
    let id_col_end_h = lines[0].find("DOMAINS").unwrap();
    let id_col_end_a = lines[1].find("example.com").unwrap();
    let id_col_end_b = lines[2].find("example.com").unwrap();
    assert_eq!(id_col_end_h, id_col_end_a);
    assert_eq!(id_col_end_a, id_col_end_b);
  }

  #[test]
  fn render_status_uses_dash_for_missing_values() {
    let cert = sample_cert("never-renewed", None, None);
    let table = render_status(&[cert]);
    assert!(table.contains("never-renewed"));
    // Missing days_until_expiry, last_renewal, status all collapse
    // to "-" so the column alignment doesn't break.
    let count_dashes = table.matches('-').count();
    assert!(count_dashes >= 3);
  }

  #[test]
  fn render_log_empty_lists_says_so() {
    assert_eq!(
      render_log("nonexistent", &[]),
      "no renewals recorded for nonexistent\n"
    );
  }

  #[test]
  fn render_log_includes_error_when_present() {
    let log = LogEntry {
      renewal_id: "renewal:01abc".to_owned(),
      started_at: chrono::Utc::now(),
      completed_at: None,
      status: "failed".to_owned(),
      error: Some("ca timeout".to_owned()),
    };
    let out = render_log("flaky", &[log]);
    assert!(out.contains("flaky"));
    assert!(out.contains("renewal:01abc"));
    assert!(out.contains("ca timeout"));
    assert!(out.contains("in progress"));
  }
}
