//! HTTP dashboard for the daemon.
//!
//! Server-side rendered with `maud`, sprinkled with `htmx` for the
//! live updates. No JS build pipeline; the page ships as one HTML
//! response and htmx polls back for fresh state. Same Arc handles
//! the control socket holds, so routes read the same data the CLI
//! reads, no duplication.
//!
//! Auth is deliberately out of scope for v0.2: the daemon's default
//! `listen_addr` is `127.0.0.1:7878`, and operators who want
//! external access put it behind their own reverse proxy with
//! whatever auth they already use (DSM, Caddy basic-auth, oauth2-
//! proxy). Avoids inventing yet-another auth layer here.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::{DateTime, Utc};
use maud::{html, Markup, DOCTYPE};
use rota_core::cert::parse_not_after;
use rota_core::protocol::{CertSummary, LogEntry};
use rota_core::Result;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::audit::AuditStore;
use crate::backends::CertBackends;
use crate::metrics;
use crate::renewer::CertRenewer;

#[derive(Clone)]
pub struct DashboardState {
  pub bundles: Arc<Vec<CertBackends>>,
  pub audit: Arc<dyn AuditStore>,
  pub renewer: Arc<CertRenewer>,
}

/// Bind and serve forever. The listener is bound by this function so
/// any error surfaces eagerly at daemon startup rather than later.
pub async fn serve(state: DashboardState, listen: &str) -> Result<()> {
  let addr: SocketAddr = listen
    .parse()
    .map_err(|e| rota_core::Error::Install(format!("invalid listen_addr {listen}: {e}")))?;
  let listener = TcpListener::bind(addr)
    .await
    .map_err(|e| rota_core::Error::Install(format!("bind {addr}: {e}")))?;
  info!(addr = %addr, "dashboard listening");

  let app = Router::new()
    .route("/", get(index))
    .route("/cert/:id", get(cert_detail))
    .route("/cert/:id/renew", post(renew_cert))
    .route("/metrics", get(metrics_endpoint))
    .with_state(state);

  axum::serve(listener, app)
    .await
    .map_err(|e| rota_core::Error::Install(format!("dashboard serve: {e}")))
}

/// GET / — cert table.
async fn index(State(state): State<DashboardState>) -> Html<String> {
  let mut summaries = Vec::with_capacity(state.bundles.len());
  for bundle in state.bundles.iter() {
    summaries.push(summarise(&state, bundle).await);
  }
  Html(layout("rota", index_body(&summaries)).into_string())
}

/// GET /cert/{id} — per-cert detail + latest audit entry.
async fn cert_detail(State(state): State<DashboardState>, Path(id): Path<String>) -> Response {
  let Some(bundle) = state.bundles.iter().find(|b| b.config.id == id) else {
    return not_found(&id);
  };
  let summary = summarise(&state, bundle).await;
  let log = match state.audit.latest_renewal(&id).await {
    Ok(Some(record)) => Some(LogEntry {
      renewal_id: record.id.0,
      started_at: record.started_at,
      completed_at: record.completed_at,
      status: record.status.as_str().to_owned(),
      error: record.error,
    }),
    _ => None,
  };
  Html(layout(&format!("rota / {id}"), detail_body(&summary, log.as_ref())).into_string())
    .into_response()
}

/// GET /metrics: Prometheus text-format scrape endpoint. Same axum
/// server as the dashboard so operators get a single port to expose
/// behind their reverse proxy.
async fn metrics_endpoint() -> Response {
  (
    [(header::CONTENT_TYPE, metrics::CONTENT_TYPE)],
    metrics::gather_text(),
  )
    .into_response()
}

/// POST /cert/{id}/renew: kick a manual renewal and redirect back.
async fn renew_cert(State(state): State<DashboardState>, Path(id): Path<String>) -> Response {
  let Some(bundle) = state.bundles.iter().find(|b| b.config.id == id) else {
    return not_found(&id);
  };
  if let Err(err) = state.renewer.run(bundle).await {
    warn!(cert = %id, error = %err, "manual renewal failed");
  }
  Redirect::to(&format!("/cert/{id}")).into_response()
}

fn not_found(id: &str) -> Response {
  (
    StatusCode::NOT_FOUND,
    Html(layout("rota", html! { p { "unknown cert: " (id) } }).into_string()),
  )
    .into_response()
}

async fn summarise(state: &DashboardState, bundle: &CertBackends) -> CertSummary {
  let install_name = bundle.install.as_ref().map(|i| i.name().to_owned());
  let (not_after, days_until_expiry) = match &bundle.install {
    Some(install) => match install.current_cert_pem(&bundle.config.id).await {
      Ok(Some(pem)) => match parse_not_after(&pem) {
        Ok(na) => (Some(na), Some((na - Utc::now()).num_days())),
        Err(_) => (None, None),
      },
      _ => (None, None),
    },
    None => (None, None),
  };
  let (last_at, last_status, last_error) = match state.audit.latest_renewal(&bundle.config.id).await
  {
    Ok(Some(r)) => (
      Some(r.started_at),
      Some(r.status.as_str().to_owned()),
      r.error,
    ),
    _ => (None, None, None),
  };
  CertSummary {
    id: bundle.config.id.clone(),
    description: bundle.config.description.clone(),
    domains: bundle.config.domains.clone(),
    ca_backend: bundle.ca.name().to_owned(),
    dcv_backend: bundle.dcv.name().to_owned(),
    install_backend: install_name,
    not_after,
    days_until_expiry,
    last_renewal_at: last_at,
    last_renewal_status: last_status,
    last_renewal_error: last_error,
  }
}

fn layout(title: &str, body: Markup) -> Markup {
  html! {
    (DOCTYPE)
    html lang="en" {
      head {
        meta charset="utf-8";
        meta name="viewport" content="width=device-width,initial-scale=1";
        title { (title) }
        script src="https://unpkg.com/htmx.org@1.9.12" {}
        style { (CSS) }
      }
      body {
        header { a href="/" { "rota" } }
        main { (body) }
      }
    }
  }
}

fn index_body(certs: &[CertSummary]) -> Markup {
  html! {
    h1 { "certs" }
    @if certs.is_empty() {
      p { "no certs configured" }
    } @else {
      table {
        thead {
          tr {
            th { "id" }
            th { "domains" }
            th { "days left" }
            th { "last renewal" }
            th { "status" }
          }
        }
        tbody {
          @for c in certs {
            tr {
              td { a href={ "/cert/" (c.id) } { (c.id) } }
              td { (c.domains.join(", ")) }
              td.warn[c.days_until_expiry.map(|d| d <= 14).unwrap_or(false)] {
                (c.days_until_expiry.map(|d| d.to_string()).unwrap_or_else(|| "-".into()))
              }
              td { (c.last_renewal_at.as_ref().map(format_ts).unwrap_or_else(|| "-".into())) }
              td.fail[c.last_renewal_status.as_deref() == Some("failed")] {
                (c.last_renewal_status.clone().unwrap_or_else(|| "-".into()))
              }
            }
          }
        }
      }
    }
  }
}

fn detail_body(c: &CertSummary, log: Option<&LogEntry>) -> Markup {
  html! {
    h1 { (c.id) }
    @if !c.description.is_empty() {
      p.muted { (c.description) }
    }
    dl {
      dt { "domains" } dd { (c.domains.join(", ")) }
      dt { "ca" } dd { (c.ca_backend) }
      dt { "dcv" } dd { (c.dcv_backend) }
      dt { "install" } dd { (c.install_backend.clone().unwrap_or_else(|| "(none)".into())) }
      dt { "not after" } dd {
        (c.not_after.as_ref().map(format_ts).unwrap_or_else(|| "-".into()))
      }
      dt { "days left" } dd {
        (c.days_until_expiry.map(|d| d.to_string()).unwrap_or_else(|| "-".into()))
      }
    }
    h2 { "latest renewal" }
    @match log {
      Some(ev) => {
        dl {
          dt { "renewal_id" } dd { (ev.renewal_id) }
          dt { "started" } dd { (format_ts(&ev.started_at)) }
          dt { "completed" } dd {
            (ev.completed_at.as_ref().map(format_ts).unwrap_or_else(|| "in progress".into()))
          }
          dt { "status" } dd { (ev.status) }
          @if let Some(err) = &ev.error {
            dt { "error" } dd { (err) }
          }
        }
      }
      None => p.muted { "no renewals recorded" }
    }
    form method="post" action={ "/cert/" (c.id) "/renew" } {
      button type="submit" { "renew now" }
    }
  }
}

fn format_ts(t: &DateTime<Utc>) -> String {
  t.format("%Y-%m-%d %H:%MZ").to_string()
}

const CSS: &str = r#"
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1rem; line-height: 1.4; }
header { padding-bottom: 1rem; border-bottom: 1px solid currentColor; margin-bottom: 1.5rem; }
header a { font-weight: 600; text-decoration: none; color: inherit; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid color-mix(in srgb, currentColor 15%, transparent); }
th { font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.04em; }
.warn { color: #b46100; font-weight: 600; }
.fail { color: #b03030; font-weight: 600; }
.muted { color: color-mix(in srgb, currentColor 60%, transparent); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.4rem 1rem; margin: 1rem 0; }
dt { font-weight: 600; }
button { font: inherit; padding: 0.4rem 1rem; border: 1px solid currentColor; background: transparent; cursor: pointer; }
button:hover { background: color-mix(in srgb, currentColor 10%, transparent); }
"#;

#[cfg(test)]
mod tests;
