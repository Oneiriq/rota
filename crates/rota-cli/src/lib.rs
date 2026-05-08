//! `rota-cli`: thin client to the rotad control socket.
//!
//! All wire work lives here so the binary in `src/main.rs` stays a
//! tiny clap-to-client adapter. Everything the binary calls is in
//! `client` (round-trip the protocol) or `format` (pretty-print
//! responses for terminal output).

pub mod client;
pub mod format;
