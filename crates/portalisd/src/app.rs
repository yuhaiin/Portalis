use crate::{
    auth::AuthState,
    db::Database,
    nft::{NftController, NftnlController},
    sysctl,
};
use anyhow::Result;
use portalis_core::{ValidationContext, parse_ssh_ports};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct Runtime {
    pub db: Arc<Mutex<Database>>,
    pub nft: Arc<dyn NftController>,
    pub auth: Arc<RwLock<AuthState>>,
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub allow_unauthenticated: bool,
}

impl Runtime {
    pub async fn open(
        data_dir: &Path,
        config_path: &Path,
        allow_unauthenticated: bool,
        web_password: Option<&str>,
    ) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::open(&data_dir.join("portalis.sqlite3"))?;
        let mut auth = AuthState::load_or_initialize(data_dir)?;
        if let Some(password) = web_password {
            if password.chars().count() < 12 {
                anyhow::bail!("web password must contain at least 12 characters");
            }
            auth.set_password(password, data_dir)?;
            tracing::info!("Portalis Web password updated from the command line");
        }
        let nft: Arc<dyn NftController> = Arc::new(NftnlController::new());
        if let Some(config) = db.active_config()? {
            let needs_restore = nft
                .status(&config)
                .map(|status| !status.table_present || status.drifted)
                .unwrap_or(true);
            if needs_restore {
                match nft.apply(&config) {
                    Ok(receipt) => {
                        tracing::info!(
                            rules = receipt.rule_count,
                            "restored active Portalis revision"
                        );
                        if let Err(error) =
                            sysctl::ensure_forwarding(&config, Path::new("/etc/sysctl.d"))
                        {
                            tracing::warn!(%error, "could not restore forwarding sysctl");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not restore active Portalis revision at startup")
                    }
                }
            }
        }
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            nft,
            auth: Arc::new(RwLock::new(auth)),
            data_dir: data_dir.to_path_buf(),
            config_path: config_path.to_path_buf(),
            allow_unauthenticated,
        })
    }

    pub fn validation_context(&self) -> ValidationContext {
        let path = std::env::var_os("PORTALIS_SSHD_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/ssh/sshd_config"));
        let content = std::fs::read_to_string(path).unwrap_or_default();
        ValidationContext {
            ssh_ports: parse_ssh_ports(&content),
        }
    }
}
