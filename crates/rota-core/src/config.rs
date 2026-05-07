//! Config schema — the `rota.yaml` data model.
//!
//! The config is a list of certs. Each cert names a CA backend, a
//! registrar backend, and an install backend by tag, plus their
//! per-instance settings. A daemon-wide section sets scheduling,
//! storage, and listen-address policy.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Top-level config — what `rota.yaml` deserializes into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotaConfig {
  #[serde(default)]
  pub daemon: DaemonConfig,
  pub certs: Vec<CertConfig>,
}

impl RotaConfig {
  /// Load a config file, returning a typed parse error on failure.
  pub fn load(path: &Path) -> Result<Self> {
    if !path.exists() {
      return Err(Error::ConfigNotFound { path: path.to_owned() });
    }
    let raw = std::fs::read_to_string(path)?;
    serde_yaml::from_str(&raw).map_err(|err| Error::ConfigParse {
      path: path.to_owned(),
      message: err.to_string(),
    })
  }

  /// Look up a cert by id.
  pub fn cert(&self, id: &str) -> Option<&CertConfig> {
    self.certs.iter().find(|c| c.id == id)
  }
}

/// Daemon-wide settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
  /// Path to the SQLite audit database.
  #[serde(default = "default_db_path")]
  pub database_path: PathBuf,
  /// HTTP listen address for the dashboard.
  #[serde(default = "default_listen_addr")]
  pub listen_addr: String,
  /// UNIX socket the CLI talks to.
  #[serde(default = "default_socket_path")]
  pub socket_path: PathBuf,
  /// How often to sweep for certs nearing expiry.
  #[serde(default = "default_check_interval_seconds")]
  pub check_interval_seconds: u64,
  /// Renew when fewer than this many days remain on the cert.
  #[serde(default = "default_renew_threshold_days")]
  pub renew_threshold_days: u32,
}

impl Default for DaemonConfig {
  fn default() -> Self {
    Self {
      database_path: default_db_path(),
      listen_addr: default_listen_addr(),
      socket_path: default_socket_path(),
      check_interval_seconds: default_check_interval_seconds(),
      renew_threshold_days: default_renew_threshold_days(),
    }
  }
}

/// Per-cert configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
  /// Stable identifier for this cert (used in logs, CLI, dashboard).
  pub id: String,
  /// Human-readable description, surfaced in the dashboard.
  #[serde(default)]
  pub description: String,
  /// FQDNs the cert covers. First entry is the CN.
  pub domains: Vec<String>,
  /// Persistent private key path (mode 600 expected). Reused across
  /// every renewal — only the cert rotates.
  pub key_path: PathBuf,
  /// CA that issues this cert.
  pub ca: CaSpec,
  /// Registrar that hosts DNS for DCV.
  pub registrar: RegistrarSpec,
  /// Where the issued cert + chain land.
  pub install: InstallSpec,
}

/// CA-backend selector. Each variant carries the backend-specific
/// settings inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaSpec {
  /// Namecheap traditional reissue API (Sectigo-backed).
  Namecheap {
    /// Numeric SSL ID from the Namecheap dashboard.
    ssl_id: u64,
    /// Path to a file containing the API key. Read at runtime so
    /// secrets never sit in the parsed config tree.
    api_key_file: PathBuf,
    /// Namecheap username (account owner).
    username: String,
  },
}

/// Registrar-backend selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistrarSpec {
  /// Namecheap-managed DNS via the registrar API.
  Namecheap {
    api_key_file: PathBuf,
    username: String,
  },
}

/// Install-backend selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallSpec {
  /// Synology DSM via `synowebapi`. The cert id surfaces in the DSM
  /// Control Panel under the configured description.
  Dsm {
    /// Description shown in DSM's Certificate panel.
    description: String,
  },
  /// Plain filesystem: write `<dir>/<id>.crt`, `<dir>/<id>.chain.crt`,
  /// and a copy of the private key with mode 600.
  Filesystem { directory: PathBuf },
}

fn default_db_path() -> PathBuf {
  PathBuf::from("/var/lib/rota/rota.db")
}

fn default_listen_addr() -> String {
  "127.0.0.1:7878".to_owned()
}

fn default_socket_path() -> PathBuf {
  PathBuf::from("/var/run/rota.sock")
}

fn default_check_interval_seconds() -> u64 {
  60 * 60 // 1 hour
}

fn default_renew_threshold_days() -> u32 {
  30
}
