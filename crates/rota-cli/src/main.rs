//! `rota` — the command-line client.
//!
//! Thin client that talks to `rotad` over a UNIX socket for
//! status/manual-renew/install operations. Designed so every action
//! the dashboard surfaces is also reachable headlessly.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rota_core::config::RotaConfig;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "rota", about = "rota CLI", version)]
struct Args {
  /// Path to rota.yaml.
  #[arg(
    short,
    long,
    env = "ROTA_CONFIG",
    default_value = "/etc/rota/rota.yaml"
  )]
  config: PathBuf,

  #[command(subcommand)]
  command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
  /// Print the parsed config and exit. Useful for debugging YAML.
  Check,
  /// List configured certs and their last-known status.
  Status,
  /// Force a renewal for one cert, or all certs with `--all`.
  Renew {
    /// Cert id to renew.
    #[arg(long, conflicts_with = "all")]
    cert: Option<String>,
    /// Renew every configured cert.
    #[arg(long, default_value_t = false)]
    all: bool,
  },
}

#[tokio::main]
async fn main() -> Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
    .init();

  let args = Args::parse();
  let config = RotaConfig::load(&args.config)?;

  match args.command {
    Command::Check => {
      println!("config ok: {} cert(s)", config.certs.len());
      for cert in &config.certs {
        println!("  - {} ({})", cert.id, cert.domains.join(", "));
      }
    }
    Command::Status => {
      // v0.1: connect to rotad over UNIX socket, fetch CertStatus list.
      println!("status command not yet implemented (v0.0.0 scaffold)");
    }
    Command::Renew { cert, all } => match (cert, all) {
      (Some(id), false) => {
        config
          .cert(&id)
          .ok_or_else(|| anyhow::anyhow!("no cert with id {id}"))?;
        println!("would renew {id} (v0.0.0 scaffold)");
      }
      (None, true) => {
        for cert in &config.certs {
          println!("would renew {} (v0.0.0 scaffold)", cert.id);
        }
      }
      _ => anyhow::bail!("pass either --cert <id> or --all"),
    },
  }

  Ok(())
}
