use crate::{app::Runtime, auth::AuthState, nft::NftError, s3, sysctl};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use portalis_core::{Config, KernelStatus, ValidationResponse};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct WebAssets;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Deserialize)]
struct PasswordRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct S3SettingsRequest {
    profile: s3::S3Profile,
    secrets: Option<s3::S3Secrets>,
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    key: String,
}

pub fn router(runtime: Runtime) -> Router {
    Router::new()
        .route("/api/v1/auth", get(auth_status))
        .route("/api/v1/auth/password", post(set_password))
        .route("/api/v1/status", get(status))
        .route("/api/v1/rules", get(rules))
        .route("/api/v1/draft", get(get_draft).put(save_draft))
        .route("/api/v1/draft/validate", post(validate))
        .route("/api/v1/apply", post(apply))
        .route("/api/v1/revisions", get(revisions))
        .route("/api/v1/rollback/{revision}", post(rollback))
        .route("/api/v1/audit", get(audit))
        .route(
            "/api/v1/settings/s3",
            get(s3_settings).put(save_s3_settings),
        )
        .route("/api/v1/backups", get(backups).post(backup))
        .route("/api/v1/backups/restore", post(restore_backup))
        .fallback(static_asset)
        .with_state(runtime.clone())
        .layer(middleware::from_fn_with_state(runtime, authenticate))
}

async fn authenticate(
    State(runtime): State<Runtime>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    if method != Method::GET && method != Method::HEAD {
        if let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            let host = request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if origin != format!("http://{host}") && origin != format!("https://{host}") {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "cross-origin mutation rejected".into(),
                    }),
                )
                    .into_response();
            }
        }
    }
    // The UI bundle contains no instance data. Let it load for a remote browser so the frontend
    // can receive the API 401 and prompt for the configured password.
    if !request.uri().path().starts_with("/api/")
        && (method == Method::GET || method == Method::HEAD)
    {
        return next.run(request).await;
    }
    if runtime.allow_unauthenticated {
        return next.run(request).await;
    }
    let remote = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let is_loopback = remote.is_none_or(AuthState::is_loopback);
    let headers = request.headers();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let password = headers
        .get("x-portalis-password")
        .and_then(|value| value.to_str().ok());
    let basic_password = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| STANDARD.decode(value).ok())
        .and_then(|value| String::from_utf8(value).ok())
        .and_then(|value| {
            value
                .split_once(':')
                .map(|(_, password)| password.to_owned())
        });
    let auth = runtime.auth.read().await;
    let authenticated = bearer.is_some_and(|token| auth.verify_token(token))
        || password.is_some_and(|value| auth.verify_password(value))
        || basic_password.is_some_and(|value| auth.verify_password(&value));
    if is_loopback || authenticated {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "authentication required; use the setup token or configured password".into(),
        }),
    )
        .into_response()
}

async fn auth_status(State(runtime): State<Runtime>) -> Response {
    let auth = runtime.auth.read().await;
    Json(serde_json::json!({ "password_enabled": auth.has_password(), "loopback_passwordless": true, "setup_token_file": auth.secret_path() })).into_response()
}

async fn set_password(
    State(runtime): State<Runtime>,
    Json(input): Json<PasswordRequest>,
) -> Response {
    if input.password.chars().count() < 12 {
        return bad_request("password must contain at least 12 characters");
    }
    let mut auth = runtime.auth.write().await;
    match auth.set_password(&input.password, &runtime.data_dir) {
        Ok(()) => Json(serde_json::json!({ "password_enabled": true })).into_response(),
        Err(error) => internal(error),
    }
}

async fn status(State(runtime): State<Runtime>) -> Response {
    let (active, draft) = {
        let db = runtime.db.lock().await;
        (db.active_revision(), db.draft_config())
    };
    let active = match active {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    let draft_revision = match draft {
        Ok(value) => value.map(|revision| revision.id),
        Err(error) => return internal(error),
    };
    let config = active
        .as_ref()
        .map(|revision| &revision.config)
        .cloned()
        .unwrap_or_default();
    let kernel = match runtime.nft.status(&config) {
        Ok(value) => value,
        Err(error) => KernelStatus {
            table_present: false,
            drifted: true,
            counters: Vec::new(),
            observed_at: format!("error: {error}"),
        },
    };
    let mut warnings = Vec::new();
    if !runtime.auth.read().await.has_password() {
        warnings.push("Loopback requests bypass password authentication; configure a password before binding Portalis beyond localhost.".to_owned());
    }
    if config.requires_ipv4_forwarding()
        && !sysctl::forwarding_state(portalis_core::AddressFamily::Ipv4)
    {
        warnings.push("IPv4 forwarding is disabled for the active configuration.".to_owned());
    }
    if config.requires_ipv6_forwarding()
        && !sysctl::forwarding_state(portalis_core::AddressFamily::Ipv6)
    {
        warnings.push("IPv6 forwarding is disabled for the active configuration.".to_owned());
    }
    if kernel.drifted {
        warnings.push(
            "The managed nftables table differs from the active revision or is absent.".to_owned(),
        );
    }
    warnings.extend(sysctl::route_warnings(&config));
    Json(serde_json::json!({
        "name": "Portalis", "version": env!("CARGO_PKG_VERSION"),
        "active_revision": active.as_ref().map(|revision| &revision.id),
        "draft_revision": draft_revision,
        "kernel": kernel,
        "ipv4_forwarding": sysctl::forwarding_state(portalis_core::AddressFamily::Ipv4),
        "ipv6_forwarding": sysctl::forwarding_state(portalis_core::AddressFamily::Ipv6),
        "warnings": warnings,
    }))
    .into_response()
}

async fn rules(State(runtime): State<Runtime>) -> Response {
    let config = match runtime.db.lock().await.active_config() {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => return internal(error),
    };
    match runtime.nft.status(&config) {
        Ok(value) => Json(value).into_response(),
        Err(error) => internal(error),
    }
}

async fn get_draft(State(runtime): State<Runtime>) -> Response {
    match runtime.db.lock().await.draft_config() {
        Ok(value) => {
            Json(value.map(|revision| revision.config).unwrap_or_default()).into_response()
        }
        Err(error) => internal(error),
    }
}

async fn save_draft(State(runtime): State<Runtime>, Json(config): Json<Config>) -> Response {
    if let Err(errors) = validate_config(&runtime, &config) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ValidationResponse {
                valid: false,
                errors: errors.into_iter().map(|error| error.to_string()).collect(),
                plan: config.plan(),
            }),
        )
            .into_response();
    }
    match runtime.db.lock().await.save_draft(&config) {
        Ok(revision) => (StatusCode::CREATED, Json(revision)).into_response(),
        Err(error) => internal(error),
    }
}

async fn validate(State(_runtime): State<Runtime>, Json(config): Json<Config>) -> Response {
    match validate_config(&_runtime, &config) {
        Ok(()) => Json(ValidationResponse {
            valid: true,
            errors: Vec::new(),
            plan: config.plan(),
        })
        .into_response(),
        Err(errors) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ValidationResponse {
                valid: false,
                errors: errors.into_iter().map(|error| error.to_string()).collect(),
                plan: config.plan(),
            }),
        )
            .into_response(),
    }
}

async fn apply(State(runtime): State<Runtime>) -> Response {
    let draft = match runtime.db.lock().await.draft_config() {
        Ok(Some(value)) => value,
        Ok(None) => return bad_request("no saved draft"),
        Err(error) => return internal(error),
    };
    if let Err(errors) = validate_config(&runtime, &draft.config) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ValidationResponse {
                valid: false,
                errors: errors.into_iter().map(|error| error.to_string()).collect(),
                plan: draft.config.plan(),
            }),
        )
            .into_response();
    }
    let previous = match runtime.db.lock().await.active_config() {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => return internal(error),
    };
    if previous == draft.config {
        if let Ok(kernel) = runtime.nft.status(&draft.config) {
            if kernel.table_present && !kernel.drifted {
                let active = match runtime.db.lock().await.active_revision() {
                    Ok(value) => value,
                    Err(error) => return internal(error),
                };
                return Json(serde_json::json!({ "active": active, "reused_kernel_rules": true }))
                    .into_response();
            }
        }
    }
    let snapshot_path = runtime.data_dir.join("snapshots").join(format!(
        "{}.json",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    ));
    if let Err(error) = std::fs::create_dir_all(snapshot_path.parent().expect("snapshot parent")) {
        return internal(error);
    }
    let snapshot = match runtime.nft.table_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return nft_error(error),
    };
    if let Err(error) = std::fs::write(&snapshot_path, snapshot) {
        return internal(error);
    }
    let receipt = match runtime.nft.apply(&draft.config) {
        Ok(receipt) => receipt,
        Err(error) => {
            let _ = runtime
                .db
                .lock()
                .await
                .mark_apply_error(&draft.id, &error.to_string());
            return nft_error(error);
        }
    };
    if let Err(error) =
        sysctl::ensure_forwarding(&draft.config, std::path::Path::new("/etc/sysctl.d"))
    {
        let rollback_error = runtime
            .nft
            .apply(&previous)
            .err()
            .map(|rollback| format!("; nft rollback failed: {rollback}"));
        let message = format!("{error}{}", rollback_error.unwrap_or_default());
        let _ = runtime
            .db
            .lock()
            .await
            .mark_apply_error(&draft.id, &message);
        return internal(message);
    }
    let active = match runtime.db.lock().await.mark_active(&draft.config) {
        Ok(value) => value,
        Err(error) => {
            let rollback = runtime
                .nft
                .apply(&previous)
                .err()
                .map(|rollback| format!("; nft rollback failed: {rollback}"));
            return internal(format!(
                "could not persist active revision: {error}{}",
                rollback.unwrap_or_default()
            ));
        }
    };
    if let Err(error) = std::fs::write(
        &runtime.config_path,
        serde_json::to_vec_pretty(&draft.config).unwrap_or_default(),
    ) {
        tracing::warn!(%error, "could not write exported Portalis config");
    }
    Json(serde_json::json!({ "active": active, "snapshot": snapshot_path, "nft": receipt }))
        .into_response()
}

async fn revisions(State(runtime): State<Runtime>) -> Response {
    match runtime.db.lock().await.revisions(100) {
        Ok(value) => Json(value).into_response(),
        Err(error) => internal(error),
    }
}

async fn rollback(Path(revision_id): Path<String>, State(runtime): State<Runtime>) -> Response {
    let revision = match runtime.db.lock().await.revision(&revision_id) {
        Ok(Some(value)) => value,
        Ok(None) => return not_found("revision not found"),
        Err(error) => return internal(error),
    };
    if let Err(errors) = validate_config(&runtime, &revision.config) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ValidationResponse {
                valid: false,
                errors: errors.into_iter().map(|error| error.to_string()).collect(),
                plan: revision.config.plan(),
            }),
        )
            .into_response();
    }
    let previous = match runtime.db.lock().await.active_config() {
        Ok(value) => value.unwrap_or_default(),
        Err(error) => return internal(error),
    };
    if let Err(error) = runtime.nft.apply(&revision.config) {
        return nft_error(error);
    }
    if let Err(error) =
        sysctl::ensure_forwarding(&revision.config, std::path::Path::new("/etc/sysctl.d"))
    {
        let rollback = runtime
            .nft
            .apply(&previous)
            .err()
            .map(|value| format!("; nft rollback failed: {value}"));
        return internal(format!("{error}{}", rollback.unwrap_or_default()));
    }
    match runtime.db.lock().await.mark_active(&revision.config) {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            let rollback = runtime
                .nft
                .apply(&previous)
                .err()
                .map(|value| format!("; nft rollback failed: {value}"));
            internal(format!(
                "could not persist rollback: {error}{}",
                rollback.unwrap_or_default()
            ))
        }
    }
}

async fn audit(State(runtime): State<Runtime>) -> Response {
    match runtime.db.lock().await.audit_entries(100) {
        Ok(value) => Json(value).into_response(),
        Err(error) => internal(error),
    }
}

async fn s3_settings(State(runtime): State<Runtime>) -> Response {
    match s3::settings(&runtime.data_dir) {
        Ok(value) => Json(value).into_response(),
        Err(error) => internal(error),
    }
}

async fn save_s3_settings(
    State(runtime): State<Runtime>,
    Json(input): Json<S3SettingsRequest>,
) -> Response {
    if (input.profile.provider != "aws" && input.profile.endpoint.trim().is_empty())
        || input.profile.bucket.trim().is_empty()
    {
        return bad_request(
            "S3 bucket is required; a custom endpoint is also required for MinIO, R2, or custom storage",
        );
    }
    if input.secrets.as_ref().is_none_or(|secrets| {
        secrets.access_key_id.trim().is_empty() || secrets.secret_access_key.trim().is_empty()
    }) && !s3::settings(&runtime.data_dir).is_ok_and(|value| value.configured)
    {
        return bad_request(
            "access key and secret key are required for the first S3 configuration",
        );
    }
    match s3::save_profile(&runtime.data_dir, &input.profile, input.secrets.as_ref()) {
        Ok(()) => Json(s3::settings(&runtime.data_dir).unwrap_or(s3::S3Settings {
            profile: None,
            configured: false,
        }))
        .into_response(),
        Err(error) => internal(error),
    }
}

async fn backups(State(runtime): State<Runtime>) -> Response {
    let local = match runtime.db.lock().await.backups(50) {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    match s3::list_backups(&runtime.data_dir).await {
        Ok(remote) => Json(serde_json::json!({ "local": local, "remote": remote })).into_response(),
        Err(error) => {
            Json(serde_json::json!({ "local": local, "remote": [], "warning": error.to_string() }))
                .into_response()
        }
    }
}

async fn backup(State(runtime): State<Runtime>) -> Response {
    let Some(revision) = (match runtime.db.lock().await.active_revision() {
        Ok(value) => value,
        Err(error) => return internal(error),
    }) else {
        return bad_request("no active revision");
    };
    match s3::upload_active(&runtime.data_dir, &revision.id, &revision.config).await {
        Ok(artifact) => {
            if let Err(error) = runtime.db.lock().await.backup_record(
                &revision.id,
                &artifact.key,
                &artifact.sha256,
                artifact.size_bytes,
                "uploaded",
                None,
            ) {
                return internal(error);
            }
            Json(artifact).into_response()
        }
        Err(error) => internal(error),
    }
}

async fn restore_backup(
    State(runtime): State<Runtime>,
    Json(input): Json<RestoreRequest>,
) -> Response {
    let config = match s3::download_config(&runtime.data_dir, &input.key).await {
        Ok(value) => value,
        Err(error) => return bad_request(&error.to_string()),
    };
    if let Err(errors) = validate_config(&runtime, &config) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ValidationResponse {
                valid: false,
                errors: errors.into_iter().map(|error| error.to_string()).collect(),
                plan: config.plan(),
            }),
        )
            .into_response();
    }
    match runtime.db.lock().await.save_draft(&config) {
        Ok(revision) => {
            Json(serde_json::json!({ "draft": revision, "requires_confirmation": true }))
                .into_response()
        }
        Err(error) => internal(error),
    }
}

fn validate_config(
    runtime: &Runtime,
    config: &Config,
) -> Result<(), Vec<portalis_core::ValidationError>> {
    config.validate(&runtime.validation_context())
}

async fn static_asset(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match WebAssets::get(path).or_else(|| WebAssets::get("index.html")) {
        Some(asset) => {
            let content_type = if path.ends_with(".js") {
                "text/javascript"
            } else if path.ends_with(".css") {
                "text/css"
            } else {
                "text/html; charset=utf-8"
            };
            ([(header::CONTENT_TYPE, content_type)], asset.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn internal(error: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
        .into_response()
}
fn nft_error(error: NftError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
        .into_response()
}
fn bad_request(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}
fn not_found(error: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}
