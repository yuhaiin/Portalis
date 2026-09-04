use anyhow::{Context, Result};
use aws_sdk_s3::{Client, primitives::ByteStream};
use aws_types::region::Region;
use chrono::Utc;
use portalis_core::{Config, RulePlan, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Profile {
    pub provider: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Secrets {
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct S3Settings {
    pub profile: Option<S3Profile>,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupArtifact {
    pub revision_id: String,
    pub key: String,
    pub sha256: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEnvelope {
    schema_version: u32,
    product: String,
    created_at: String,
    revision_id: String,
    config: Config,
    nft_plan: Vec<RulePlan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBackup {
    pub key: String,
    pub size_bytes: i64,
    pub last_modified: Option<String>,
}

pub fn load_profile(data_dir: &Path) -> Result<Option<(S3Profile, S3Secrets)>> {
    let profile_path = data_dir.join("s3-profile.json");
    let secret_path = data_dir.join("s3-secrets.json");
    if !profile_path.exists() || !secret_path.exists() {
        return Ok(None);
    }
    Ok(Some((
        serde_json::from_slice(&fs::read(profile_path)?)?,
        serde_json::from_slice(&fs::read(secret_path)?)?,
    )))
}

pub fn save_profile(
    data_dir: &Path,
    profile: &S3Profile,
    secrets: Option<&S3Secrets>,
) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    fs::write(
        data_dir.join("s3-profile.json"),
        serde_json::to_vec_pretty(profile)?,
    )?;
    if let Some(secrets) = secrets {
        let path = data_dir.join("s3-secrets.json");
        fs::write(&path, serde_json::to_vec(secrets)?)?;
        restrict_file(&path)?;
    }
    restrict_file(&data_dir.join("s3-profile.json"))?;
    Ok(())
}

pub fn settings(data_dir: &Path) -> Result<S3Settings> {
    let profile = load_profile(data_dir)?.map(|(profile, _)| profile);
    Ok(S3Settings {
        configured: profile.is_some(),
        profile,
    })
}

pub async fn upload_active(
    data_dir: &Path,
    revision_id: &str,
    config: &Config,
) -> Result<BackupArtifact> {
    let Some((profile, secrets)) = load_profile(data_dir)? else {
        anyhow::bail!("S3 profile is not configured")
    };
    let envelope = BackupEnvelope {
        schema_version: SCHEMA_VERSION,
        product: "Portalis".to_owned(),
        created_at: Utc::now().to_rfc3339(),
        revision_id: revision_id.to_owned(),
        config: config.clone(),
        nft_plan: config.plan(),
    };
    let json = serde_json::to_vec(&envelope)?;
    let compressed = zstd::stream::encode_all(json.as_slice(), 3)?;
    let checksum = hex::encode(Sha256::digest(&compressed));
    let prefix = profile.prefix.trim_matches('/');
    let key = if prefix.is_empty() {
        format!("revisions/{revision_id}.json.zst")
    } else {
        format!("{prefix}/revisions/{revision_id}.json.zst")
    };

    let base = load_config(&profile, &secrets).await;
    let client = client_from_profile(&profile, &secrets, &base);
    client
        .put_object()
        .bucket(&profile.bucket)
        .key(&key)
        .content_type("application/zstd")
        .metadata("sha256", checksum.clone())
        .body(ByteStream::from(compressed.clone()))
        .send()
        .await
        .context("upload Portalis backup")?;
    prune_old_backups(&client, &profile, 10).await?;
    Ok(BackupArtifact {
        revision_id: revision_id.into(),
        key,
        sha256: checksum,
        size_bytes: compressed.len(),
    })
}

pub async fn list_backups(data_dir: &Path) -> Result<Vec<RemoteBackup>> {
    let Some((profile, secrets)) = load_profile(data_dir)? else {
        anyhow::bail!("S3 profile is not configured")
    };
    let base = load_config(&profile, &secrets).await;
    let client = client_from_profile(&profile, &secrets, &base);
    let prefix = profile.prefix.trim_matches('/');
    let prefix = if prefix.is_empty() {
        "revisions/".to_owned()
    } else {
        format!("{prefix}/revisions/")
    };
    let mut result = Vec::new();
    let mut paginator = client
        .list_objects_v2()
        .bucket(&profile.bucket)
        .prefix(prefix)
        .into_paginator()
        .send();
    while let Some(page) = paginator.next().await {
        for object in page?.contents() {
            if let Some(key) = object.key() {
                result.push(RemoteBackup {
                    key: key.to_owned(),
                    size_bytes: object.size().unwrap_or_default(),
                    last_modified: object.last_modified().map(ToString::to_string),
                });
            }
        }
    }
    result.sort_by(|left, right| right.last_modified.cmp(&left.last_modified));
    Ok(result)
}

pub async fn download_config(data_dir: &Path, key: &str) -> Result<Config> {
    let Some((profile, secrets)) = load_profile(data_dir)? else {
        anyhow::bail!("S3 profile is not configured")
    };
    let prefix = profile.prefix.trim_matches('/');
    let allowed_prefix = if prefix.is_empty() {
        "revisions/".to_owned()
    } else {
        format!("{prefix}/revisions/")
    };
    if !key.starts_with(&allowed_prefix) || key.contains("..") {
        anyhow::bail!("backup key is outside the Portalis backup prefix")
    }
    let base = load_config(&profile, &secrets).await;
    let client = client_from_profile(&profile, &secrets, &base);
    let output = client
        .get_object()
        .bucket(&profile.bucket)
        .key(key)
        .send()
        .await
        .context("download Portalis backup")?;
    let expected = output
        .metadata()
        .and_then(|metadata| metadata.get("sha256"))
        .cloned();
    let compressed = output.body.collect().await?.into_bytes().to_vec();
    let actual = hex::encode(Sha256::digest(&compressed));
    if expected.as_deref().is_some_and(|value| value != actual) {
        anyhow::bail!("backup checksum mismatch")
    }
    let json = zstd::stream::decode_all(compressed.as_slice())?;
    let envelope: BackupEnvelope = serde_json::from_slice(&json)?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.product != "Portalis" {
        anyhow::bail!("unsupported Portalis backup format")
    }
    Ok(envelope.config)
}

async fn load_config(profile: &S3Profile, secrets: &S3Secrets) -> aws_config::SdkConfig {
    let mut builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(profile.region.clone()))
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            &secrets.access_key_id,
            &secrets.secret_access_key,
            None,
            None,
            "Portalis",
        ));
    if !profile.endpoint.trim().is_empty() {
        builder = builder.endpoint_url(profile.endpoint.clone());
    }
    builder.load().await
}

fn client_from_profile(
    profile: &S3Profile,
    _secrets: &S3Secrets,
    base: &aws_config::SdkConfig,
) -> Client {
    let config = aws_sdk_s3::config::Builder::from(base)
        .force_path_style(profile.path_style)
        .build();
    Client::from_conf(config)
}

async fn prune_old_backups(client: &Client, profile: &S3Profile, keep: usize) -> Result<()> {
    let prefix = profile.prefix.trim_matches('/');
    let prefix = if prefix.is_empty() {
        "revisions/".to_owned()
    } else {
        format!("{prefix}/revisions/")
    };
    let mut objects = Vec::new();
    let mut paginator = client
        .list_objects_v2()
        .bucket(&profile.bucket)
        .prefix(prefix)
        .into_paginator()
        .send();
    while let Some(page) = paginator.next().await {
        let page = page?;
        objects.extend(page.contents().iter().filter_map(|object| {
            object.key().map(|key| {
                (
                    key.to_owned(),
                    object.last_modified().map(ToString::to_string),
                )
            })
        }));
    }
    objects.sort_by(|left, right| right.1.cmp(&left.1));
    for (key, _) in objects.into_iter().skip(keep) {
        client
            .delete_object()
            .bucket(&profile.bucket)
            .key(key)
            .send()
            .await?;
    }
    Ok(())
}

fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a disposable MinIO endpoint in PORTALIS_S3_ENDPOINT"]
    async fn minio_round_trip() {
        let Some(endpoint) = std::env::var_os("PORTALIS_S3_ENDPOINT") else {
            return;
        };
        let data_dir = std::env::temp_dir().join(format!("portalis-s3-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data_dir).unwrap();
        let profile = S3Profile {
            provider: "minio".into(),
            endpoint: endpoint.to_string_lossy().into_owned(),
            region: "us-east-1".into(),
            bucket: "portalis-test".into(),
            prefix: "integration".into(),
            path_style: true,
        };
        let secrets = S3Secrets {
            access_key_id: "minioadmin".into(),
            secret_access_key: "minioadmin".into(),
        };
        save_profile(&data_dir, &profile, Some(&secrets)).unwrap();
        let base = load_config(&profile, &secrets).await;
        let client = client_from_profile(&profile, &secrets, &base);
        client
            .create_bucket()
            .bucket(&profile.bucket)
            .send()
            .await
            .unwrap();
        let config = Config::default();
        let artifact = upload_active(&data_dir, "integration-revision", &config)
            .await
            .unwrap();
        assert_eq!(list_backups(&data_dir).await.unwrap()[0].key, artifact.key);
        assert_eq!(
            download_config(&data_dir, &artifact.key).await.unwrap(),
            config
        );
    }
}
