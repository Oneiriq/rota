//! UNIX-socket client for the rotad control protocol.
//!
//! One round-trip per invocation: connect, send one JSON line, read
//! one JSON line, close. Matches the daemon's per-connection model
//! and means the CLI is fast even when rotad is busy.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use rota_core::protocol::{Request, Response, PROTOCOL_VERSION};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Send one request over the daemon's control socket and return the
/// parsed response. Errors carry enough context that the operator
/// can see what went wrong without grepping through `rotad` logs.
pub async fn send_request(socket: &Path, request: &Request) -> Result<Response> {
  let stream = UnixStream::connect(socket).await.with_context(|| {
    format!(
      "connect to rota daemon socket at {} (is rotad running?)",
      socket.display()
    )
  })?;
  let (read, mut write) = stream.into_split();

  let mut payload = serde_json::to_vec(request).context("serialise request")?;
  payload.push(b'\n');
  write
    .write_all(&payload)
    .await
    .context("write request to socket")?;
  write.flush().await.context("flush request")?;

  let mut reader = BufReader::new(read);
  let mut line = String::new();
  let n = reader.read_line(&mut line).await.context("read response")?;
  if n == 0 {
    return Err(anyhow!("daemon closed the socket without responding"));
  }

  let response: Response =
    serde_json::from_str(line.trim_end()).context("parse response from rotad")?;

  if let Some(version) = response_protocol_version(&response) {
    if version != PROTOCOL_VERSION {
      return Err(anyhow!(
        "protocol version mismatch: daemon speaks v{version}, CLI speaks v{PROTOCOL_VERSION}",
      ));
    }
  }

  Ok(response)
}

fn response_protocol_version(r: &Response) -> Option<u32> {
  Some(match r {
    Response::Status {
      protocol_version, ..
    } => *protocol_version,
    Response::Renew {
      protocol_version, ..
    } => *protocol_version,
    Response::Log {
      protocol_version, ..
    } => *protocol_version,
    Response::Error {
      protocol_version, ..
    } => *protocol_version,
  })
}
