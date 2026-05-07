//! Namecheap CA + DNS registrar backends.
//!
//! Both back ends share a single HTTP client because the same API
//! key + username + allowlisted client IP authenticates both surfaces
//! at Namecheap. Construction is split so a `CertConfig` can name
//! either or both as needed without paying the connection setup cost
//! twice.

mod ca;
mod client;
mod registrar;
mod xml;

pub use ca::NamecheapCa;
pub use client::{NamecheapClient, NamecheapCreds};
pub use registrar::NamecheapRegistrar;
