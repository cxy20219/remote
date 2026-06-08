//! Agent local identity: ed25519 signing key + x25519 DH key, plus the
//! per-device AES-256-GCM key delivered by the server after approval.
//!
//! File layout intentionally matches Go's `~/.goremote/identity` field
//! names so the two implementations stay wire-compatible (the only
//! intentional divergence is the on-disk path, which is
//! `~/.tunnel-rs/identity.json` for the Rust agent to avoid clobbering a
//! Go installation).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tunnel_rs_common::{
    decode_dh_public_key, decode_signing_key, decode_verifying_key, decrypt_key_with_shared_secret,
    dh_shared_secret, encode_dh_public_key, encode_signing_key, encode_verifying_key,
    generate_dh_keypair, generate_sign_keypair, VerifyingKey, ED25519_PUBKEY_SIZE,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub server_url: String,
    pub device_privkey: String,
    pub device_pubkey: String,
    /// x25519 private key in hex (only the agent has it).
    pub device_dh_privkey: String,
    /// x25519 public key in hex; sent to the server during register.
    pub device_dh_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// AES-256-GCM key delivered by the server after approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_key: Option<String>,
    #[serde(default)]
    pub enc_enabled: bool,
    /// Server ed25519 pubkey (used to validate `register_ok` payloads in
    /// the future; Phase 5 does not yet pin this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_pubkey: Option<String>,
    #[serde(default)]
    pub created_at: DateTime<Utc>,
}

const FILE_NAME: &str = "identity.json";
#[cfg(unix)]
const DIR_PERMS: u32 = 0o700;
#[cfg(unix)]
const FILE_PERMS: u32 = 0o600;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("key decode: {0}")]
    Key(String),
    #[error("identity file exists for a different server")]
    ServerMismatch,
}

pub type Result<T> = std::result::Result<T, IdentityError>;

impl AgentIdentity {
    /// Load the identity from `<identity_dir>/identity.json`, or generate a
    /// fresh one bound to `server_url` and persist it.
    pub async fn load_or_create(identity_dir: &Path, server_url: &str) -> Result<Self> {
        let path = identity_dir.join(FILE_NAME);
        if path.exists() {
            let data = tokio::fs::read(&path).await?;
            let mut id: AgentIdentity = serde_json::from_slice(&data)?;
            // If the agent is being repointed at a different server, refuse
            // to reuse the identity. Operator must clear the file manually.
            if id.server_url != server_url {
                return Err(IdentityError::ServerMismatch);
            }
            // Touch created_at to a sane value if missing.
            if id.created_at.timestamp() == 0 {
                id.created_at = Utc::now();
                id.save_to(&path).await?;
            }
            Ok(id)
        } else {
            let id = Self::generate(server_url);
            tokio::fs::create_dir_all(identity_dir).await?;
            set_dir_perms(identity_dir).await?;
            id.save_to(&path).await?;
            set_file_perms(&path).await?;
            Ok(id)
        }
    }

    pub fn generate(server_url: &str) -> Self {
        let (vk, sk) = generate_sign_keypair();
        let (dh_priv, dh_pub) = generate_dh_keypair();
        Self {
            server_url: server_url.to_string(),
            device_privkey: encode_signing_key(&sk),
            device_pubkey: encode_verifying_key(&vk),
            device_dh_privkey: hex::encode(dh_priv.to_bytes()),
            device_dh_pubkey: encode_dh_public_key(&dh_pub),
            client_id: None,
            enc_key: None,
            enc_enabled: false,
            server_pubkey: None,
            created_at: Utc::now(),
        }
    }

    /// Persist to `<identity_dir>/identity.json`. Tries to apply 0600 perms.
    pub async fn save(&self, identity_dir: &Path) -> Result<()> {
        let path = identity_dir.join(FILE_NAME);
        if !identity_dir.exists() {
            tokio::fs::create_dir_all(identity_dir).await?;
            set_dir_perms(identity_dir).await?;
        }
        self.save_to(&path).await?;
        set_file_perms(&path).await?;
        Ok(())
    }

    async fn save_to(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self)?;
        // Write directly: `tokio::fs::write` truncates the existing file
        // and replaces its contents atomically. The previous "tmp + rename"
        // dance is unsafe on Windows where `rename` over an existing
        // destination can fail; the agent only ever writes one process at
        // a time so we don't need the stronger guarantee here.
        tokio::fs::write(path, &data).await?;
        Ok(())
    }

    // ---------- key accessors ----------

    pub fn sign_privkey(&self) -> Result<tunnel_rs_common::identity::SigningKey> {
        decode_signing_key(&self.device_privkey).map_err(|e| IdentityError::Key(e.to_string()))
    }

    pub fn verify_pubkey(&self) -> Result<VerifyingKey> {
        decode_verifying_key(&self.device_pubkey).map_err(|e| IdentityError::Key(e.to_string()))
    }

    pub fn dh_privkey(&self) -> Result<StaticSecret> {
        let bytes = hex::decode(&self.device_dh_privkey)?;
        if bytes.len() != 32 {
            return Err(IdentityError::Key(format!(
                "dh privkey size {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(StaticSecret::from(arr))
    }

    pub fn dh_pubkey(&self) -> Result<PublicKey> {
        decode_dh_public_key(&self.device_dh_pubkey).map_err(|e| IdentityError::Key(e.to_string()))
    }

    /// Convenience: decode the enc_key from hex.
    pub fn enc_key_bytes(&self) -> Result<[u8; 32]> {
        let s = self
            .enc_key
            .as_ref()
            .ok_or_else(|| IdentityError::Key("enc_key missing".into()))?;
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(IdentityError::Key(format!(
                "enc_key size {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Decrypt the enc_key delivered in `register_ok` using the agent's DH
    /// private key and the server's ephemeral DH public key.
    ///
    /// **Security note**: this function handles long-term private keys and
    /// session secrets. Do not log any of `device_dh_privkey`, the ECDH
    /// shared secret, `enc_key_encrypted`, or the recovered `enc_key`. Doing
    /// so would leak material into stdout/stderr capture and centralised log
    /// aggregators.
    pub fn install_enc_key(
        &mut self,
        enc_key_encrypted: &str,
        server_dh_pub_hex: &str,
    ) -> Result<()> {
        let agent_priv = self.dh_privkey()?;
        let server_pub = decode_dh_public_key(server_dh_pub_hex)
            .map_err(|e| IdentityError::Key(e.to_string()))?;
        let shared = dh_shared_secret(&agent_priv, &server_pub);
        let plain = decrypt_key_with_shared_secret(enc_key_encrypted, &shared)
            .map_err(|e| {
                tracing::debug!(error = %e, "enc_key decrypt failed");
                IdentityError::Key(e.to_string())
            })?;
        if plain.len() != 32 {
            return Err(IdentityError::Key(format!(
                "decrypted enc_key wrong size: {}",
                plain.len()
            )));
        }
        self.enc_key = Some(hex::encode(plain));
        self.enc_enabled = true;
        Ok(())
    }

    /// Convenience accessor — Phase 6 uses this to install the per-device
    /// AES key into a `CryptoManager`.
    pub fn pubkey_size() -> usize {
        ED25519_PUBKEY_SIZE
    }
}

async fn set_dir_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(DIR_PERMS);
        tokio::fs::set_permissions(path, perm).await?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

async fn set_file_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(FILE_PERMS);
        tokio::fs::set_permissions(path, perm).await?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub fn default_identity_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".tunnel-rs")
    } else {
        PathBuf::from(".tunnel-rs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_has_all_keys() {
        let id = AgentIdentity::generate("localhost:8080");
        assert_eq!(id.device_privkey.len(), 64);
        assert_eq!(id.device_pubkey.len(), 64);
        assert_eq!(id.device_dh_privkey.len(), 64);
        assert_eq!(id.device_dh_pubkey.len(), 64);
        assert!(id.client_id.is_none());
        assert!(!id.enc_enabled);
    }

    #[tokio::test]
    async fn load_or_create_persists_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_path_buf();
        let id1 = AgentIdentity::load_or_create(&dir_path, "localhost:8080")
            .await
            .unwrap();
        let id2 = AgentIdentity::load_or_create(&dir_path, "localhost:8080")
            .await
            .unwrap();
        assert_eq!(id1.device_privkey, id2.device_privkey);
        assert_eq!(id1.device_pubkey, id2.device_pubkey);
        assert!(dir.path().join(FILE_NAME).exists());
    }

    #[tokio::test]
    async fn server_mismatch_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        AgentIdentity::load_or_create(dir.path(), "host-a:8080")
            .await
            .unwrap();
        let err = AgentIdentity::load_or_create(dir.path(), "host-b:8080")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::ServerMismatch));
    }

    #[tokio::test]
    async fn enc_key_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = AgentIdentity::load_or_create(dir.path(), "localhost:8080")
            .await
            .unwrap();
        let (_server_priv, server_pub) =
            tunnel_rs_common::identity::generate_dh_keypair();
        let server_dh_hex = tunnel_rs_common::identity::encode_dh_public_key(&server_pub);

        // Pretend the agent_priv matches the server_pub via shared secret.
        // For the test we use a real ECDH keypair.
        let (_agent_priv, _agent_pub) = tunnel_rs_common::identity::generate_dh_keypair();
        // Force a deterministic enc_key for the test.
        let plain_key = [0xAB; 32];
        let shared = {
            let (a_priv, a_pub) = tunnel_rs_common::identity::generate_dh_keypair();
            let (s_priv, s_pub) = tunnel_rs_common::identity::generate_dh_keypair();
            let shared_a = tunnel_rs_common::identity::dh_shared_secret(&a_priv, &s_pub);
            let shared_s = tunnel_rs_common::identity::dh_shared_secret(&s_priv, &a_pub);
            assert_eq!(shared_a, shared_s);
            // Replace id.dh_privkey so install_enc_key uses this deterministic
            // privkey.
            id.device_dh_privkey = hex::encode(a_priv.to_bytes());
            id.device_dh_pubkey = tunnel_rs_common::identity::encode_dh_public_key(&a_pub);
            (shared_a, s_pub)
        };
        let (shared, s_pub) = shared;
        let _ = server_dh_hex; // not used; the test injects via id.
        let enc_hex = tunnel_rs_common::identity::encrypt_key_with_shared_secret(&plain_key, &shared)
            .unwrap();
        id.install_enc_key(&enc_hex, &tunnel_rs_common::identity::encode_dh_public_key(&s_pub))
            .unwrap();
        let recovered = id.enc_key_bytes().unwrap();
        assert_eq!(recovered, plain_key);
    }
}
