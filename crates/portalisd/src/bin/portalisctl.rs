//! Root/portalis-group local client for the daemon's Unix control socket.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use std::path::PathBuf;
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
#[command(name = "portalisctl", about = "Local Portalis control client")]
struct Cli {
    #[arg(long, default_value = "/run/portalis/control.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    Rules,
    Apply,
    Backups,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let (method, path, body) = match cli.command {
        Command::Status => (http::Method::GET, "/api/v1/status", None),
        Command::Rules => (http::Method::GET, "/api/v1/rules", None),
        Command::Apply => (http::Method::POST, "/api/v1/apply", Some("{}")),
        Command::Backups => (http::Method::GET, "/api/v1/backups", None),
    };
    let stream = UnixStream::connect(&cli.socket)
        .await
        .with_context(|| format!("connect control socket {}", cli.socket.display()))?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "control socket connection closed");
        }
    });
    let request = if let Some(body) = body {
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_owned())).boxed())?
    } else {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Empty::<Bytes>::new().boxed())?
    };
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    println!("{}", String::from_utf8_lossy(&bytes));
    if !status.is_success() {
        anyhow::bail!("control request failed with {status}")
    }
    Ok(())
}
