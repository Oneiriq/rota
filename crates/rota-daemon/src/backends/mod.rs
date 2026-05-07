//! Concrete backend implementations + the dispatch that turns a
//! `RotaConfig` into a set of trait objects ready for the scheduler
//! to drive.
//!
//! Each submodule implements one or more of the traits in
//! `rota_core::backend`. Adding a new vendor is a sibling module that
//! impls the relevant trait and an arm in [`build_ca`] /
//! [`build_registrar`] / [`build_install`].

pub mod dsm;
pub mod filesystem;
pub mod namecheap;

use std::sync::Arc;

use rota_core::backend::{CABackend, InstallBackend, RegistrarBackend};
use rota_core::config::{
  CaSpec, CertConfig, InstallSpec, NamecheapAccount, RegistrarSpec, RotaConfig,
};
use rota_core::{Error, Result};

use dsm::DsmInstall;
use filesystem::FilesystemInstall;
use namecheap::{NamecheapCa, NamecheapClient, NamecheapCreds, NamecheapRegistrar};

/// All backends bound to one `CertConfig`. Owns the lifetime of the
/// trait objects so the scheduler can hand them around freely.
pub struct CertBackends {
  pub config: CertConfig,
  pub ca: Arc<dyn CABackend>,
  pub registrar: Arc<dyn RegistrarBackend>,
  pub install: Option<Arc<dyn InstallBackend>>,
}

/// Build the full backend set from a parsed config.
///
/// The Namecheap HTTP client is constructed once per call and shared
/// across every cert that names Namecheap as its CA or registrar.
/// Matches Namecheap's rate-limit model and avoids redundant
/// connection setup.
pub fn build_from_config(config: &RotaConfig) -> Result<Vec<CertBackends>> {
  let namecheap_client = match &config.namecheap {
    Some(account) => Some(build_namecheap_client(account)?),
    None => None,
  };

  let mut bundles = Vec::with_capacity(config.certs.len());
  for cert in &config.certs {
    let ca = build_ca(&cert.ca, namecheap_client.as_ref())?;
    let registrar = build_registrar(&cert.registrar, namecheap_client.as_ref())?;
    let install = build_install(&cert.install, cert)?;
    bundles.push(CertBackends {
      config: cert.clone(),
      ca,
      registrar,
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

fn build_ca(
  spec: &CaSpec,
  namecheap_client: Option<&Arc<NamecheapClient>>,
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
  }
}

fn build_registrar(
  spec: &RegistrarSpec,
  namecheap_client: Option<&Arc<NamecheapClient>>,
) -> Result<Arc<dyn RegistrarBackend>> {
  match spec {
    RegistrarSpec::Namecheap => {
      let client = namecheap_client.ok_or_else(|| {
        Error::ConfigInvalid(
          "cert names namecheap registrar but config is missing top-level `namecheap` block".into(),
        )
      })?;
      Ok(Arc::new(NamecheapRegistrar::new(Arc::clone(client))))
    }
  }
}

fn build_install(spec: &InstallSpec, cert: &CertConfig) -> Result<Option<Arc<dyn InstallBackend>>> {
  match spec {
    InstallSpec::Dsm { description } => Ok(Some(Arc::new(DsmInstall::new(description.clone())))),
    InstallSpec::Filesystem { directory } => Ok(Some(Arc::new(FilesystemInstall::new(
      directory.clone(),
      cert.id.clone(),
    )))),
  }
}
