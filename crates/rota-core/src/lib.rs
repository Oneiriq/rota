//! Core types, traits, and config schema for rota.
//!
//! Three abstractions decouple the renewal pipeline from any one CA,
//! DCV strategy, or install target:
//!
//! - [`backend::CABackend`]: issues certificates from a Certificate
//!   Authority (Namecheap traditional reissue, Let's Encrypt /
//!   ZeroSSL / BuyPass via ACME).
//! - [`backend::DcvBackend`]: satisfies the CA's domain-control
//!   challenge. DNS-01 solvers (Namecheap, Cloudflare) publish TXT
//!   records; HTTP-01 solvers expose a token at a well-known URL.
//! - [`backend::InstallBackend`]: places issued certs where the
//!   system that serves them can read them (DSM, plain filesystem,
//!   nginx reload, HAProxy runtime API, Kubernetes Secret).
//!
//! Each [`config::CertConfig`] picks one of each, so a fleet of
//! self-hosted sites across mixed DCV strategies and hosts runs
//! through the same renewal pipeline.

pub mod backend;
pub mod cert;
pub mod cluster;
pub mod config;
pub mod error;
pub mod protocol;
pub mod secrets;

pub use error::{Error, Result};
