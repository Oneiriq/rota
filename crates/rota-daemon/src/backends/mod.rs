//! Concrete backend implementations + the dispatch that turns a
//! `RotaConfig` into a set of trait objects ready for the scheduler
//! to drive.
//!
//! Each submodule implements one or more of the traits in
//! `rota_core::backend`. Adding a new vendor is a sibling module that
//! impls the relevant trait and an arm in [`build_ca`] /
//! [`build_dcv`] / [`build_install`].

pub mod acme;
pub mod cloudflare;
pub mod dsm;
pub mod email;
pub mod filesystem;
pub mod haproxy;
pub mod k8s;
pub mod namecheap;
pub mod nginx;
pub mod webhook;

use std::sync::Arc;

use rota_core::backend::{AlertBackend, CABackend, DcvBackend, InstallBackend};
use rota_core::config::{
  AlertSpec, CaSpec, CertConfig, CloudflareAccount, DcvSpec, InstallSpec, NamecheapAccount,
  RotaConfig,
};
use rota_core::{Error, Result};

use acme::AcmeCa;
use cloudflare::{CloudflareClient, CloudflareDcv};
use dsm::DsmInstall;
use email::{EmailAlert, EmailAlertParams};
use filesystem::FilesystemInstall;
use haproxy::HaproxyInstall;
use k8s::K8sSecretInstall;
use namecheap::{NamecheapCa, NamecheapClient, NamecheapCreds, NamecheapDcv};
use nginx::NginxInstall;
use webhook::{WebhookAlert, WebhookAlertParams};

/// All backends bound to one `CertConfig`. Owns the lifetime of the
/// trait objects so the scheduler can hand them around freely.
pub struct CertBackends {
  pub config: CertConfig,
  pub ca: Arc<dyn CABackend>,
  pub dcv: Arc<dyn DcvBackend>,
  pub install: Option<Arc<dyn InstallBackend>>,
}

/// Build the full backend set from a parsed config.
///
/// The Namecheap HTTP client is constructed once per call and shared
/// across every cert that names Namecheap as its CA or DCV solver.
/// Matches Namecheap's rate-limit model and avoids redundant
/// connection setup.
pub async fn build_from_config(config: &RotaConfig) -> Result<Vec<CertBackends>> {
  let namecheap_client = match &config.namecheap {
    Some(account) => Some(build_namecheap_client(account)?),
    None => None,
  };
  let cloudflare_client = match &config.cloudflare {
    Some(account) => Some(build_cloudflare_client(account)?),
    None => None,
  };
  let acme_ca = match &config.acme {
    Some(spec) => Some(Arc::new(AcmeCa::from_spec(spec).await?)),
    None => None,
  };

  let mut bundles = Vec::with_capacity(config.certs.len());
  for cert in &config.certs {
    let ca = build_ca(&cert.ca, namecheap_client.as_ref(), acme_ca.as_ref())?;
    let dcv = build_dcv(
      &cert.dcv,
      namecheap_client.as_ref(),
      cloudflare_client.as_ref(),
    )?;
    let install = build_install(&cert.install, cert).await?;
    bundles.push(CertBackends {
      config: cert.clone(),
      ca,
      dcv,
      install,
    });
  }
  Ok(bundles)
}

fn build_namecheap_client(account: &NamecheapAccount) -> Result<Arc<NamecheapClient>> {
  let api_key = std::fs::read_to_string(&account.api_key_file)
    .map_err(|e| {
      Error::ConfigInvalid(format!(
        "namecheap api_key_file {}: {e}",
        account.api_key_file.display()
      ))
    })?
    .trim()
    .to_owned();
  let creds = NamecheapCreds {
    api_user: account
      .api_user
      .clone()
      .unwrap_or_else(|| account.username.clone()),
    api_key,
    username: account.username.clone(),
    client_ip: account.client_ip.clone(),
  };
  Ok(NamecheapClient::new(creds).into_arc())
}

fn build_cloudflare_client(account: &CloudflareAccount) -> Result<Arc<CloudflareClient>> {
  let token = std::fs::read_to_string(&account.api_token_file)
    .map_err(|e| {
      Error::ConfigInvalid(format!(
        "cloudflare api_token_file {}: {e}",
        account.api_token_file.display()
      ))
    })?
    .trim()
    .to_owned();
  Ok(CloudflareClient::new(token).into_arc())
}

fn build_ca(
  spec: &CaSpec,
  namecheap_client: Option<&Arc<NamecheapClient>>,
  acme_ca: Option<&Arc<AcmeCa>>,
) -> Result<Arc<dyn CABackend>> {
  match spec {
    CaSpec::Namecheap { ssl_id } => {
      let client = namecheap_client.ok_or_else(|| {
        Error::ConfigInvalid(
          "cert names namecheap CA but config is missing top-level `namecheap` block".into(),
        )
      })?;
      Ok(Arc::new(NamecheapCa::new(Arc::clone(client), *ssl_id)))
    }
    CaSpec::Acme => {
      let ca = acme_ca.ok_or_else(|| {
        Error::ConfigInvalid(
          "cert names acme CA but config is missing top-level `acme` block".into(),
        )
      })?;
      Ok(Arc::clone(ca) as Arc<dyn CABackend>)
    }
  }
}

fn build_dcv(
  spec: &DcvSpec,
  namecheap_client: Option<&Arc<NamecheapClient>>,
  cloudflare_client: Option<&Arc<CloudflareClient>>,
) -> Result<Arc<dyn DcvBackend>> {
  match spec {
    DcvSpec::Namecheap => {
      let client = namecheap_client.ok_or_else(|| {
        Error::ConfigInvalid(
          "cert names namecheap dcv but config is missing top-level `namecheap` block".into(),
        )
      })?;
      Ok(Arc::new(NamecheapDcv::new(Arc::clone(client))))
    }
    DcvSpec::Cloudflare => {
      let client = cloudflare_client.ok_or_else(|| {
        Error::ConfigInvalid(
          "cert names cloudflare dcv but config is missing top-level `cloudflare` block".into(),
        )
      })?;
      Ok(Arc::new(CloudflareDcv::new(Arc::clone(client))))
    }
  }
}

async fn build_install(
  spec: &InstallSpec,
  cert: &CertConfig,
) -> Result<Option<Arc<dyn InstallBackend>>> {
  match spec {
    InstallSpec::Dsm { description } => Ok(Some(Arc::new(DsmInstall::new(description.clone())))),
    InstallSpec::Filesystem { directory } => Ok(Some(Arc::new(FilesystemInstall::new(
      directory.clone(),
      cert.id.clone(),
    )))),
    InstallSpec::Nginx {
      directory,
      reload_command,
    } => Ok(Some(Arc::new(NginxInstall::new(
      directory.clone(),
      cert.id.clone(),
      reload_command.clone(),
    )))),
    InstallSpec::Haproxy {
      directory,
      socket_path,
      cert_storage_name,
    } => Ok(Some(Arc::new(HaproxyInstall::new(
      directory.clone(),
      cert.id.clone(),
      socket_path.clone(),
      cert_storage_name.clone(),
    )))),
    InstallSpec::K8sSecret {
      namespace,
      secret_name,
      kubeconfig_path,
    } => {
      let install = K8sSecretInstall::new(
        namespace.clone(),
        secret_name.clone(),
        kubeconfig_path.clone(),
      )
      .await?;
      Ok(Some(Arc::new(install)))
    }
  }
}

/// Build daemon-wide alert sinks from `RotaConfig::alerts`. Empty
/// input returns an empty vec (silent operation).
pub fn build_alerts(specs: &[AlertSpec]) -> Result<Vec<Arc<dyn AlertBackend>>> {
  let mut out = Vec::with_capacity(specs.len());
  for spec in specs {
    out.push(build_alert(spec)?);
  }
  Ok(out)
}

fn build_alert(spec: &AlertSpec) -> Result<Arc<dyn AlertBackend>> {
  match spec {
    AlertSpec::Email {
      smtp_host,
      smtp_port,
      tls,
      username,
      password_file,
      from,
      to,
    } => {
      let password = std::fs::read_to_string(password_file)
        .map_err(|e| {
          Error::ConfigInvalid(format!(
            "email alert password_file {}: {e}",
            password_file.display()
          ))
        })?
        .trim()
        .to_owned();
      let alert = EmailAlert::new(EmailAlertParams {
        smtp_host: smtp_host.as_str(),
        smtp_port: *smtp_port,
        tls: *tls,
        username: username.as_str(),
        password: &password,
        from: from.as_str(),
        to,
      })?;
      Ok(Arc::new(alert))
    }
    AlertSpec::Webhook {
      url,
      bearer_token_file,
      timeout_seconds,
    } => {
      let bearer_token = match bearer_token_file {
        None => None,
        Some(path) => {
          let token = std::fs::read_to_string(path)
            .map_err(|e| {
              Error::ConfigInvalid(format!(
                "webhook alert bearer_token_file {}: {e}",
                path.display()
              ))
            })?
            .trim()
            .to_owned();
          Some(token)
        }
      };
      let timeout = timeout_seconds.map(std::time::Duration::from_secs);
      let alert = WebhookAlert::new(WebhookAlertParams {
        url: url.as_str(),
        bearer_token: bearer_token.as_deref(),
        timeout,
      })?;
      Ok(Arc::new(alert))
    }
  }
}
