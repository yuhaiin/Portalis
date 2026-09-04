use crate::{api, app::Runtime, s3, sysctl};
use anyhow::{Context, Result};
use axum::serve as axum_serve;
use portalis_core::AddressFamily;
use std::{net::SocketAddr, path::Path};
use tokio::net::{TcpListener, UnixListener};

pub async fn serve(runtime: Runtime, listen: &str, control_socket: &Path) -> Result<()> {
    let address: SocketAddr = listen
        .parse()
        .with_context(|| format!("parse Portalis listen address {listen}"))?;
    if runtime.allow_unauthenticated {
        tracing::warn!(
            %address,
            "Portalis Web authentication is disabled; anyone who can reach this address can change nftables rules"
        );
    }
    tracing::info!(%address, "Portalis listening");
    let listener = TcpListener::bind(address)
        .await
        .context("bind Portalis Web address")?;
    let web = api::router(runtime.clone());
    let socket_path = control_socket.to_path_buf();
    let control_runtime = runtime.clone();
    tokio::spawn(async move {
        if let Err(error) = serve_control(control_runtime, socket_path).await {
            tracing::error!(%error, "Portalis control socket stopped");
        }
    });
    tokio::spawn(backup_scheduler(runtime));
    axum_serve(
        listener,
        web.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("serve Portalis Web API")?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::warn!(%error, "could not listen for Ctrl-C");
            }
        }
        _ = terminate.recv() => {}
    }
    tracing::info!("Portalis shutdown signal received");
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "could not listen for Ctrl-C");
    }
    tracing::info!("Portalis shutdown signal received");
}

async fn serve_control(runtime: Runtime, socket_path: std::path::PathBuf) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("remove stale control socket {}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind control socket {}", socket_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;
    }
    tracing::info!(path = %socket_path.display(), "Portalis control socket listening");
    axum_serve(listener, api::router(runtime))
        .await
        .context("serve Portalis control API")?;
    Ok(())
}

async fn backup_scheduler(runtime: Runtime) {
    loop {
        let now = chrono::Local::now();
        let next = (now + chrono::Duration::days(1))
            .date_naive()
            .and_hms_opt(3, 0, 0)
            .expect("valid backup time");
        let wait = (next
            .and_local_timezone(chrono::Local)
            .single()
            .unwrap_or(now)
            - now)
            .to_std()
            .unwrap_or_default();
        tokio::time::sleep(wait).await;
        if let Err(error) = backup_active_if_new(&runtime).await {
            tracing::warn!(%error, "scheduled Portalis backup failed");
        }
    }
}

pub async fn backup_active_if_new(runtime: &Runtime) -> Result<bool> {
    let Some(revision) = runtime.db.lock().await.active_revision()? else {
        return Ok(false);
    };
    if runtime
        .db
        .lock()
        .await
        .has_successful_backup(&revision.id)?
    {
        return Ok(false);
    }
    match s3::upload_active(&runtime.data_dir, &revision.id, &revision.config).await {
        Ok(artifact) => {
            runtime.db.lock().await.backup_record(
                &revision.id,
                &artifact.key,
                &artifact.sha256,
                artifact.size_bytes,
                "uploaded",
                None,
            )?;
            Ok(true)
        }
        Err(error) => {
            runtime.db.lock().await.backup_record(
                &revision.id,
                "",
                "",
                0,
                "failed",
                Some(&error.to_string()),
            )?;
            Err(error)
        }
    }
}

pub async fn print_status(runtime: &Runtime) -> Result<()> {
    let config = runtime.db.lock().await.active_config()?.unwrap_or_default();
    let status = runtime.nft.status(&config)?;
    println!("Portalis {}", env!("CARGO_PKG_VERSION"));
    println!(
        "table_present={} drifted={}",
        status.table_present, status.drifted
    );
    println!(
        "ipv4_forwarding={} ipv6_forwarding={}",
        sysctl::forwarding_state(AddressFamily::Ipv4),
        sysctl::forwarding_state(AddressFamily::Ipv6)
    );
    println!(
        "counters={}",
        serde_json::to_string_pretty(&status.counters)?
    );
    Ok(())
}

pub async fn print_rules(runtime: &Runtime) -> Result<()> {
    let config = runtime.db.lock().await.active_config()?.unwrap_or_default();
    println!("{}", serde_json::to_string_pretty(&config)?);
    println!(
        "kernel={}",
        serde_json::to_string_pretty(&runtime.nft.status(&config)?)?
    );
    Ok(())
}

pub async fn apply_draft(runtime: &Runtime) -> Result<()> {
    let draft = runtime
        .db
        .lock()
        .await
        .draft_config()?
        .context("no saved draft")?;
    draft
        .config
        .validate(&runtime.validation_context())
        .map_err(|errors| {
            anyhow::anyhow!(
                "{}",
                errors
                    .into_iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
    let previous = runtime.db.lock().await.active_config()?.unwrap_or_default();
    if previous == draft.config {
        if let Ok(kernel) = runtime.nft.status(&draft.config) {
            if kernel.table_present && !kernel.drifted {
                println!("active rules already match the saved draft");
                return Ok(());
            }
        }
    }
    if let Ok(snapshot) = runtime.nft.table_snapshot() {
        std::fs::write(runtime.data_dir.join("pre-apply.json"), snapshot)?;
    }
    let receipt = runtime.nft.apply(&draft.config)?;
    if let Err(error) =
        sysctl::ensure_forwarding(&draft.config, std::path::Path::new("/etc/sysctl.d"))
    {
        let rollback = runtime
            .nft
            .apply(&previous)
            .err()
            .map(|value| format!("; nft rollback failed: {value}"));
        return Err(anyhow::anyhow!("{error}{}", rollback.unwrap_or_default()));
    }
    let active = match runtime.db.lock().await.mark_active(&draft.config) {
        Ok(active) => active,
        Err(error) => {
            let _ = runtime.nft.apply(&previous);
            return Err(error);
        }
    };
    println!(
        "active revision {} ({} kernel rules, replaced_existing_table={})",
        active.id, receipt.rule_count, receipt.replaced_existing_table
    );
    Ok(())
}

pub async fn rollback(runtime: &Runtime, revision_id: &str) -> Result<()> {
    let revision = runtime
        .db
        .lock()
        .await
        .revision(revision_id)?
        .context("revision not found")?;
    let previous = runtime.db.lock().await.active_config()?.unwrap_or_default();
    runtime.nft.apply(&revision.config)?;
    if let Err(error) =
        sysctl::ensure_forwarding(&revision.config, std::path::Path::new("/etc/sysctl.d"))
    {
        let rollback = runtime
            .nft
            .apply(&previous)
            .err()
            .map(|value| format!("; nft rollback failed: {value}"));
        return Err(anyhow::anyhow!("{error}{}", rollback.unwrap_or_default()));
    }
    let active = match runtime.db.lock().await.mark_active(&revision.config) {
        Ok(active) => active,
        Err(error) => {
            let rollback = runtime
                .nft
                .apply(&previous)
                .err()
                .map(|value| format!("; nft rollback failed: {value}"));
            return Err(anyhow::anyhow!(
                "could not persist rollback: {error}{}",
                rollback.unwrap_or_default()
            ));
        }
    };
    println!(
        "rolled back to {} as active revision {}",
        revision_id, active.id
    );
    Ok(())
}

pub async fn backup(runtime: &Runtime) -> Result<()> {
    let config = runtime
        .db
        .lock()
        .await
        .active_revision()?
        .context("no active revision")?;
    let artifact = s3::upload_active(&runtime.data_dir, &config.id, &config.config).await?;
    runtime.db.lock().await.backup_record(
        &config.id,
        &artifact.key,
        &artifact.sha256,
        artifact.size_bytes,
        "uploaded",
        None,
    )?;
    println!("uploaded {} ({})", artifact.key, artifact.sha256);
    Ok(())
}
