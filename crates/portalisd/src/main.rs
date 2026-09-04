//! Portalis daemon and emergency CLI.

mod api;
mod app;
mod auth;
mod db;
mod nft;
mod s3;
mod service;
mod sysctl;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(
    name = "portalis",
    version,
    about = "Safe single-host nftables port forwarding"
)]
struct Cli {
    #[arg(long, env = "PORTALIS_DATA_DIR", default_value = "/var/lib/portalis")]
    data_dir: PathBuf,
    #[arg(
        long,
        env = "PORTALIS_CONFIG",
        default_value = "/etc/portalis/config.json"
    )]
    config: PathBuf,
    #[arg(long, env = "PORTALIS_LISTEN", default_value = "127.0.0.1:17890")]
    listen: String,
    /// Disable Web authentication. Only use this on a trusted or isolated network.
    #[arg(long, env = "PORTALIS_ALLOW_UNAUTHENTICATED", default_value_t = false)]
    allow_unauthenticated: bool,
    /// Set or replace the persisted Web password before serving.
    #[arg(
        long = "web-password",
        visible_alias = "password",
        env = "PORTALIS_WEB_PASSWORD",
        value_name = "PASSWORD",
        hide_env_values = true
    )]
    web_password: Option<String>,
    #[arg(
        long,
        env = "PORTALIS_CONTROL_SOCKET",
        default_value = "/run/portalis/control.sock"
    )]
    control_socket: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the Web API and frontend.
    Serve,
    /// Print service and kernel status.
    Status,
    /// Print the current managed rules and counters.
    Rules,
    /// Apply the saved draft revision.
    Apply,
    /// Roll back to an active revision.
    Rollback { revision: String },
    /// Upload the active revision to S3.
    Backup,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "portalis=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Serve);
    if cli.allow_unauthenticated && cli.web_password.is_some() {
        anyhow::bail!("--allow-unauthenticated cannot be combined with --web-password");
    }
    if cli.web_password.is_some() && !matches!(&command, Command::Serve) {
        anyhow::bail!("--web-password can only be used with the serve command");
    }
    let runtime = app::Runtime::open(
        &cli.data_dir,
        &cli.config,
        cli.allow_unauthenticated,
        cli.web_password.as_deref(),
    )
    .await?;
    match command {
        Command::Serve => service::serve(runtime, &cli.listen, &cli.control_socket).await,
        Command::Status => service::print_status(&runtime).await,
        Command::Rules => service::print_rules(&runtime).await,
        Command::Apply => service::apply_draft(&runtime).await,
        Command::Rollback { revision } => service::rollback(&runtime, &revision).await,
        Command::Backup => service::backup(&runtime).await,
    }
}
