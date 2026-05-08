//! SMTP email alert backend.
//!
//! Sends one-message-per-event over a configured SMTP relay. TLS mode
//! is operator-selectable: STARTTLS (port 587), implicit TLS (port
//! 465), or plaintext for a localhost relay. Auth is username +
//! password-from-file; the daemon never holds the password in the
//! parsed config tree.
//!
//! The transport is built once at daemon startup and reused for every
//! dispatch, so the connection pool and resolver state stay warm
//! across alerts.

use std::sync::Arc;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use rota_core::backend::{AlertBackend, AlertEvent};
use rota_core::config::SmtpTls;
use rota_core::secrets::redact;
use rota_core::{Error, Result};
use tracing::info;

#[derive(Clone)]
pub struct EmailAlert {
  transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
  from: Mailbox,
  to: Vec<Mailbox>,
}

impl std::fmt::Debug for EmailAlert {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("EmailAlert")
      .field("from", &self.from)
      .field("to", &self.to)
      .finish_non_exhaustive()
  }
}

/// Knobs the constructor needs. Pulled out so `build_from_config` can
/// pass typed values without depending on the full `AlertSpec` enum.
pub struct EmailAlertParams<'a> {
  pub smtp_host: &'a str,
  pub smtp_port: u16,
  pub tls: SmtpTls,
  pub username: &'a str,
  pub password: &'a str,
  pub from: &'a str,
  pub to: &'a [String],
}

impl EmailAlert {
  pub fn new(params: EmailAlertParams<'_>) -> Result<Self> {
    if params.to.is_empty() {
      return Err(Error::ConfigInvalid(
        "email alert config requires at least one `to` recipient".into(),
      ));
    }

    let from: Mailbox = params
      .from
      .parse()
      .map_err(|e| Error::ConfigInvalid(format!("email alert `from` ({}): {e}", params.from)))?;
    let to = params
      .to
      .iter()
      .map(|addr| {
        addr
          .parse::<Mailbox>()
          .map_err(|e| Error::ConfigInvalid(format!("email alert `to` ({addr}): {e}")))
      })
      .collect::<Result<Vec<_>>>()?;

    let creds = Credentials::new(params.username.to_owned(), params.password.to_owned());

    let builder = match params.tls {
      SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(params.smtp_host)
        .map_err(|e| Error::Alert(format!("smtp starttls relay: {e}")))?,
      SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(params.smtp_host)
        .map_err(|e| Error::Alert(format!("smtp implicit-tls relay: {e}")))?,
      SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(params.smtp_host),
    };

    let transport = builder.port(params.smtp_port).credentials(creds).build();

    Ok(Self {
      transport: Arc::new(transport),
      from,
      to,
    })
  }
}

#[async_trait]
impl AlertBackend for EmailAlert {
  fn name(&self) -> &str {
    "email"
  }

  async fn dispatch(&self, event: &AlertEvent) -> Result<()> {
    let subject = format!("[rota] {} {}", event.kind.as_str(), event.cert_id);
    let body = format!(
      "cert: {}\nkind: {}\ntime: {}\n\n{}\n",
      event.cert_id,
      event.kind.as_str(),
      event.timestamp.to_rfc3339(),
      event.message,
    );

    let mut builder = Message::builder().from(self.from.clone()).subject(subject);
    for recipient in &self.to {
      builder = builder.to(recipient.clone());
    }
    let message = builder
      .body(body)
      .map_err(|e| Error::Alert(format!("build email: {e}")))?;

    self
      .transport
      .send(message)
      .await
      .map_err(|e| Error::Alert(format!("smtp send: {}", redact(&e.to_string()))))?;

    info!(
      cert = %event.cert_id,
      kind = event.kind.as_str(),
      recipients = self.to.len(),
      "email alert dispatched"
    );
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn base_params() -> EmailAlertParams<'static> {
    EmailAlertParams {
      smtp_host: "smtp.example.com",
      smtp_port: 587,
      tls: SmtpTls::Starttls,
      username: "u",
      password: "p",
      from: "rota@example.com",
      to: &[],
    }
  }

  #[test]
  fn rejects_empty_recipients() {
    let err = EmailAlert::new(base_params()).expect_err("empty `to` must fail");
    let msg = err.to_string();
    assert!(msg.contains("at least one"), "got: {msg}");
  }

  #[test]
  fn rejects_invalid_from_address() {
    let to = ["ok@example.com".to_owned()];
    let mut p = base_params();
    p.from = "not-an-address";
    p.to = &to;
    let err = EmailAlert::new(p).expect_err("invalid from must fail");
    assert!(err.to_string().contains("from"), "got: {err}");
  }

  #[test]
  fn rejects_invalid_to_address() {
    let to = ["not-an-address".to_owned()];
    let mut p = base_params();
    p.to = &to;
    let err = EmailAlert::new(p).expect_err("invalid to must fail");
    assert!(err.to_string().contains("to"), "got: {err}");
  }

  #[test]
  fn debug_does_not_leak_password() {
    let to = ["ok@example.com".to_owned()];
    let mut p = base_params();
    p.password = "supersecret";
    p.to = &to;
    let alert = EmailAlert::new(p).unwrap();
    let dbg = format!("{alert:?}");
    assert!(
      !dbg.contains("supersecret"),
      "debug repr leaked password: {dbg}"
    );
  }

  #[test]
  fn accepts_starttls_implicit_and_none() {
    let to = ["ok@example.com".to_owned()];
    for tls in [SmtpTls::Starttls, SmtpTls::Implicit, SmtpTls::None] {
      let mut p = base_params();
      p.tls = tls;
      p.to = &to;
      EmailAlert::new(p).unwrap_or_else(|e| panic!("tls {tls:?} construction failed: {e}"));
    }
  }
}
