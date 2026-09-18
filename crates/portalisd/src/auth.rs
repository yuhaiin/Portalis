use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct AuthState {
    secret_path: PathBuf,
    password_hash: Option<String>,
}

impl AuthState {
    pub fn load_or_initialize(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let secret_path = data_dir.join("web-auth.secret");
        let password_path = data_dir.join("web-auth.hash");
        let password_hash = std::fs::read_to_string(&password_path)
            .ok()
            .map(|value| value.trim().to_owned());
        if !secret_path.exists() {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes)
                .map_err(|error| anyhow::anyhow!("generate web auth secret: {error}"))?;
            std::fs::write(&secret_path, URL_SAFE_NO_PAD.encode(bytes))?;
        }
        restrict_file(&secret_path)?;
        if password_hash.is_some() {
            restrict_file(&password_path)?;
        }
        Ok(Self {
            secret_path,
            password_hash,
        })
    }

    pub fn is_loopback(address: IpAddr) -> bool {
        address.is_loopback()
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let Some(hash) = &self.password_hash else {
            return false;
        };
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    pub fn verify_credential(&self, credential: &str) -> bool {
        self.verify_token(credential) || self.verify_password(credential)
    }

    pub fn set_password(&mut self, password: &str, data_dir: &Path) -> Result<()> {
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes)
            .map_err(|error| anyhow::anyhow!("generate password salt: {error}"))?;
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|error| anyhow::anyhow!("encode password salt: {error}"))?;
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| anyhow::anyhow!("hash password: {error}"))?
            .to_string();
        let path = data_dir.join("web-auth.hash");
        std::fs::write(&path, hash.as_bytes())?;
        restrict_file(&path)?;
        self.password_hash = Some(hash);
        Ok(())
    }

    pub fn has_password(&self) -> bool {
        self.password_hash.is_some()
    }
    pub fn secret_path(&self) -> &Path {
        &self.secret_path
    }

    pub fn verify_token(&self, token: &str) -> bool {
        std::fs::read_to_string(&self.secret_path).is_ok_and(|value| value.trim() == token)
    }
}

fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AuthState;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn setup_token_is_accepted_as_credential() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!("portalis-auth-test-{suffix}"));
        let auth = AuthState::load_or_initialize(&data_dir).expect("initialize auth state");
        let token = std::fs::read_to_string(auth.secret_path()).expect("read setup token");
        let accepted = auth.verify_credential(token.trim());
        std::fs::remove_dir_all(&data_dir).expect("remove auth test data");
        assert!(accepted);
    }
}
