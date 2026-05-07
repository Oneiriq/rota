use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
  #[error("config file not found at {path}")]
  ConfigNotFound { path: PathBuf },

  #[error("config parse error in {path}: {message}")]
  ConfigParse { path: PathBuf, message: String },

  #[error("config invalid: {0}")]
  ConfigInvalid(String),

  #[error("cert {id} not found in config")]
  CertNotFound { id: String },

  #[error("CA backend error: {0}")]
  Ca(String),

  #[error("registrar backend error: {0}")]
  Registrar(String),

  #[error("install backend error: {0}")]
  Install(String),

  #[error("io error: {0}")]
  Io(#[from] std::io::Error),

  #[error("serde error: {0}")]
  Serde(String),
}

impl From<serde_yaml::Error> for Error {
  fn from(err: serde_yaml::Error) -> Self {
    Self::Serde(err.to_string())
  }
}
