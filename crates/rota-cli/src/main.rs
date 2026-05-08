//! `rota`: the command-line client.
//!
//! Thin clap-to-socket adapter. Every action the dashboard surfaces
//! is reachable here too; the daemon enforces the same authz
//! (socket file mode 0o600) so headless ops are safe to script.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use rota_cli::client::send_request;
use rota_cli::format::{render_log, render_status};
use rota_core::config::RotaConfig;
use rota_core::protocol::{RenewalOutcome, Request, Response};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "rota", about = "rota CLI", version)]
struct Args {
  /// Path to rota.yaml. The CLI reads it to discover the daemon's
  /// `socket_path`; pass `--socket` to override.
  #[arg(
    short,
    long,
    env = "ROTA_CONFIG",
    default_value = "/etc/rota/rota.yaml"
  )]
  config: PathBuf,

  /// Override the daemon socket path. Useful when running rotad in
  /// a non-default location or in an integration test.
  #[arg(long)]
  socket: Option<PathBuf>,

  #[command(subcommand)]
  command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
  /// Print the parsed config and exit. Useful for debugging YAML.
  Check,
  /// List configured certs and their last-known status.
  Status,
  /// Force a renewal for one cert.
  Renew {
    /// Cert id to renew.
    #[arg(long)]
    cert: String,
  },
  /// Show the latest renewal log entry for one cert.
  Log {
    /// Cert id to inspect.
    cert: String,
  },
}

#[tokio::main]
async fn main() -> ExitCode {
  match run().await {
    Ok(code) => code,
    Err(err) => {
      eprintln!("rota: {err:#}");
      ExitCode::from(1)
    }
  }
}

async fn run() -> Result<ExitCode> {
  tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
    .with_writer(std::io::stderr)
    .init();

  let args = Args::parse();

  // Check is the only subcommand that doesn't need the daemon.
  if let Command::Check = &args.command {
    let config = RotaConfig::load(&args.config)?;
    println!("config ok: {} cert(s)", config.certs.len());
    for cert in &config.certs {
      println!("  - {} ({})", cert.id, cert.domains.join(", "));
    }
    return Ok(ExitCode::SUCCESS);
  }

  let socket = match args.socket {
    Some(p) => p,
    None => RotaConfig::load(&args.config)?.daemon.socket_path,
  };

  match args.command {
    Command::Check => unreachable!(),
    Command::Status => {
      let resp = send_request(&socket, &Request::Status).await?;
      match resp {
        Response::Status { certs, .. } => {
          print!("{}", render_status(&certs));
          Ok(ExitCode::SUCCESS)
        }
        Response::Error { message, .. } => Err(anyhow!("daemon error: {message}")),
        other => Err(anyhow!("unexpected response: {other:?}")),
      }
    }
    Command::Renew { cert } => {
      let resp = send_request(
        &socket,
        &Request::Renew {
          cert_id: cert.clone(),
        },
      )
      .await?;
      match resp {
        Response::Renew {
          renewal_id,
          outcome,
          ..
        } => match outcome {
          RenewalOutcome::Success => {
            println!("renewal succeeded for {cert} (renewal_id={renewal_id})");
            Ok(ExitCode::SUCCESS)
          }
          RenewalOutcome::Failed => {
            eprintln!("renewal failed for {cert} (renewal_id={renewal_id})");
            eprintln!("(see `rota log {cert}` for the audit trail)");
            Ok(ExitCode::from(2))
          }
        },
        Response::Error { message, .. } => Err(anyhow!("daemon error: {message}")),
        other => Err(anyhow!("unexpected response: {other:?}")),
      }
    }
    Command::Log { cert } => {
      let resp = send_request(
        &socket,
        &Request::Log {
          cert_id: cert.clone(),
          limit: None,
        },
      )
      .await
      .with_context(|| format!("fetch log for {cert}"))?;
      match resp {
        Response::Log {
          cert_id, events, ..
        } => {
          print!("{}", render_log(&cert_id, &events));
          Ok(ExitCode::SUCCESS)
        }
        Response::Error { message, .. } => Err(anyhow!("daemon error: {message}")),
        other => Err(anyhow!("unexpected response: {other:?}")),
      }
    }
  }
}
