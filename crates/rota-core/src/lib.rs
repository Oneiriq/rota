//! Core types, traits, and config schema for rota.
//!
//! Three abstractions decouple the renewal pipeline from any one CA,
//! registrar, or install target:
//!
//! - [`backend::CABackend`]: issues certificates from a Certificate
//!   Authority (Namecheap traditional reissue API today; Let's Encrypt
//!   via ACME, Sectigo direct, ZeroSSL, GoDaddy on the roadmap).
//! - [`backend::RegistrarBackend`]: manages DNS records for DCV
//!   (Namecheap today; Cloudflare, Route 53, DigitalOcean, Porkbun on
//!   the roadmap).
//! - [`backend::InstallBackend`]: places issued certs where the
//!   system that serves them can read them (DSM via synowebapi and
//!   plain filesystem today; Kubernetes Secret, nginx reload, HAProxy
//!   on the roadmap).
//!
//! Each [`config::CertConfig`] picks one of each, so a fleet of
//! self-hosted sites across mixed registrars and hosts runs through
//! the same renewal pipeline.

pub mod backend;
pub mod cert;
pub mod config;
pub mod error;
pub mod secrets;

pub use error::{Error, Result};
