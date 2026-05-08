//! `rota-daemon`: the daemon-side library `rotad` is built on top of.
//!
//! Each module is staged so successive PRs can layer onto the same
//! crate without churning the public surface:
//!
//! - [`audit`]: SQLite-backed renewal log. Source of truth for the
//!   dashboard and the operator's grep target when something fails.
//! - [`backends`]: trait-object dispatch from a parsed `RotaConfig`
//!   to the concrete CA / registrar / install backends defined in
//!   their respective submodules.
//! - [`renewer`]: drives one cert through the full renewal pipeline
//!   and emits audit events at each step.
//!
//! The thin `rotad` binary in `src/main.rs` wires these together
//! with config loading and tracing setup. The scheduler loop, CLI
//! socket, and dashboard land in follow-up PRs and plug in here.

pub mod audit;
pub mod backends;
pub mod cluster;
pub mod dashboard;
pub mod metrics;
pub mod renewer;
pub mod scheduler;
pub mod socket;
