//! Device state machine: pending → authorized, plus register, reauth, approve,
//! deny, delete. Mirrors `internal/server/device_mgr.go` but talks through
//! `Arc<StateStore>` for the durable state and `tokio::sync::mpsc` for
//! pushing the encrypted `register_ok` back to a still-open pending WebSocket.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use tokio::sync::mpsc;
use tunnel_rs_common::{
    identity, CommonError, CryptoManager, VerifyingKey, ED25519_PUBKEY_SIZE,
};
use uuid::Uuid;
use x25519_dalek::{PublicKey as DhPublic, StaticSecret as DhSecret};

use crate::error::{Result, ServerError};
use crate::persist::StateStore;
use crate::state::{DeviceState, DeviceStatus};

/// Outgoing message variant the server pushes to an agent over WebSocket.
#[derive(Debug, Clone)]
pub enum ServerOutMsg {
    Text(String),
    Binary(Vec<u8>),
}


/// Reference to a pending agent's open WebSocket. The actual `WebSocket` is
/// owned by the connection task; it pumps `ServerOutMsg` from `rx` into the
/// socket and exposes `tx` to the rest of the server (e.g. for the approve
/// endpoint to deliver `register_ok`).
pub struct PendingConn {
    pub tx: mpsc::UnboundedSender<ServerOutMsg>,
    pub remote_ip: String,
}

#[derive(Debug, Clone)]
pub struct ReauthError {
    pub reason: String,
}

const REAUTH_TIMESTAMP_DRIFT: Duration = Duration::from_secs(5 * 60);

pub struct DeviceManager {
    store: Arc<StateStore>,
    crypto_mgr: Arc<CryptoManager>,
    pending_conns: RwLock<std::collections::HashMap<String, PendingConn>>,
}

impl DeviceManager {
    pub fn new(store: Arc<StateStore>, crypto_mgr: Arc<CryptoManager>) -> Self {
        // Re-install any pre-existing device keys (no-op for fresh stores;
        // Phase 4 will need this when loading from disk).
        let mut mgr = Self {
            store,
            crypto_mgr,
            pending_conns: RwLock::new(std::collections::HashMap::new()),
        };
        mgr.rehydrate_crypto_keys();
        mgr
    }

    fn rehydrate_crypto_keys(&mut self) {
        for d in self.store.list_devices() {
            if matches!(d.status, DeviceStatus::Authorized) && !d.enc_key.is_empty() {
                if let Ok(bytes) = hex::decode(&d.enc_key) {
                    if let Err(e) = self.crypto_mgr.set_key(&d.id, &bytes) {
                        tracing::warn!(
                            device_id = %d.id,
                            error = %e,
                            "failed to rehydrate enc_key"
                        );
                    }
                }
            }
        }
    }

    // ---------- register / reauth ----------

    /// First-time register. If a pending device already exists with the same
    /// signing pubkey, reuse its `client_id`; otherwise mint a new one.
    pub fn register_new(
        &self,
        device_sign_pubkey: &str,
        device_dh_pubkey: &str,
        hostname: &str,
        os_name: &str,
        remote_ip: &str,
    ) -> Result<DeviceState> {
        validate_sign_pubkey_hex(device_sign_pubkey)?;
        validate_dh_pubkey_hex(device_dh_pubkey)?;

        if let Some(mut existing) = self.store.find_device_by_sign_pubkey(device_sign_pubkey) {
            self.store.update_device(&existing.id, |d| {
                if !hostname.is_empty() {
                    d.hostname = hostname.to_string();
                    d.name = hostname.to_string();
                }
                if !os_name.is_empty() {
                    d.os = os_name.to_string();
                }
                if !device_dh_pubkey.is_empty() {
                    d.device_dh_pubkey = device_dh_pubkey.to_string();
                }
            });
            if let Some(updated) = self.store.get_device(&existing.id) {
                existing = updated;
            }
            tracing::info!(
                device_id = %existing.id,
                hostname = %existing.hostname,
                ip = %remote_ip,
                "re-registered pending device"
            );
            return Ok(existing);
        }

        let id = format!("client-{}", &Uuid::new_v4().to_string()[..8]);
        let device = DeviceState {
            id: id.clone(),
            name: if hostname.is_empty() {
                id.clone()
            } else {
                hostname.to_string()
            },
            device_sign_pubkey: device_sign_pubkey.to_string(),
            device_dh_pubkey: device_dh_pubkey.to_string(),
            hostname: hostname.to_string(),
            os: os_name.to_string(),
            status: DeviceStatus::Pending,
            enc_key: String::new(),
            enc_enabled: false,
            ip_whitelist: Vec::new(),
            first_seen: Utc::now(),
            approved_at: None,
        };
        self.store.insert_device(device.clone());
        tracing::info!(
            device_id = %id,
            hostname = %device.hostname,
            ip = %remote_ip,
            "new device pending approval"
        );
        Ok(device)
    }

    /// Reauth attempt by an already-authorized device.
    pub fn reauth(
        &self,
        client_id: &str,
        device_sign_pubkey: &str,
        timestamp: i64,
        signature_hex: &str,
    ) -> std::result::Result<DeviceState, ReauthError> {
        let device = self
            .store
            .get_device(client_id)
            .ok_or_else(|| ReauthError {
                reason: format!("device not found: {client_id}"),
            })?;

        if device.device_sign_pubkey != device_sign_pubkey {
            return Err(ReauthError {
                reason: "public key mismatch".to_string(),
            });
        }

        if !matches!(device.status, DeviceStatus::Authorized) {
            return Err(ReauthError {
                reason: format!("device is not authorized: {}", crate::error::status_str(device.status)),
            });
        }

        let pub_bytes = hex::decode(&device.device_sign_pubkey)
            .map_err(|e| ReauthError { reason: format!("invalid stored pubkey: {e}") })?;
        if pub_bytes.len() != ED25519_PUBKEY_SIZE {
            return Err(ReauthError {
                reason: "invalid stored pubkey size".to_string(),
            });
        }
        let mut arr = [0u8; ED25519_PUBKEY_SIZE];
        arr.copy_from_slice(&pub_bytes);
        let vk = VerifyingKey::from_bytes(&arr).map_err(|e| ReauthError {
            reason: format!("invalid verifying key: {e}"),
        })?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| ReauthError { reason: format!("invalid signature format: {e}") })?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| ReauthError {
            reason: format!("invalid signature bytes: {e}"),
        })?;

        if !identity::verify_timestamp(&vk, client_id, timestamp, &sig) {
            return Err(ReauthError {
                reason: "signature verification failed".to_string(),
            });
        }
        if !identity::is_timestamp_valid(timestamp, REAUTH_TIMESTAMP_DRIFT.as_secs() as i64) {
            return Err(ReauthError {
                reason: "timestamp expired".to_string(),
            });
        }

        Ok(device)
    }

    // ---------- approve / deny / delete ----------

    /// Approve a pending device. Generates an enc_key, ECDH-encrypts it for the
    /// agent, and returns `(device, enc_key_encrypted_hex, server_dh_pubkey_hex)`
    /// so the caller can ship them in `register_ok`.
    pub fn approve(&self, device_id: &str) -> Result<(DeviceState, String, String)> {
        let device = self
            .store
            .get_device(device_id)
            .ok_or_else(|| ServerError::DeviceNotFound(device_id.to_string()))?;

        if !matches!(device.status, DeviceStatus::Pending) {
            return Err(ServerError::DeviceNotPending(device_id.to_string()));
        }
        if device.device_dh_pubkey.is_empty() {
            return Err(ServerError::DeviceMissingDhPubkey);
        }

        let enc_key = identity::generate_enc_key();
        let agent_pub_bytes = hex::decode(&device.device_dh_pubkey)
            .map_err(CommonError::from)
            .map_err(ServerError::from)?;
        if agent_pub_bytes.len() != 32 {
            return Err(ServerError::Internal(format!(
                "invalid agent dh pubkey size: {}",
                agent_pub_bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&agent_pub_bytes);
        let agent_pub = DhPublic::from(arr);

        let server_priv = DhSecret::random_from_rng(OsRng);
        let server_pub = DhPublic::from(&server_priv);
        let shared = identity::dh_shared_secret(&server_priv, &agent_pub);

        let enc_key_encrypted =
            identity::encrypt_key_with_shared_secret(&enc_key, &shared).map_err(ServerError::from)?;
        let server_dh_pubkey_hex = identity::encode_dh_public_key(&server_pub);

        self.store.update_device(device_id, |d| {
            d.status = DeviceStatus::Authorized;
            d.enc_key = hex::encode(enc_key);
            d.enc_enabled = true;
            d.approved_at = Some(Utc::now());
        });
        self.crypto_mgr.set_key(device_id, &enc_key).map_err(ServerError::from)?;

        let updated = self
            .store
            .get_device(device_id)
            .ok_or_else(|| ServerError::DeviceNotFound(device_id.to_string()))?;
        Ok((updated, enc_key_encrypted, server_dh_pubkey_hex))
    }

    pub fn deny(&self, device_id: &str) -> Result<()> {
        self.take_pending_conn(device_id);
        if !self.store.remove_device(device_id) {
            return Err(ServerError::DeviceNotFound(device_id.to_string()));
        }
        Ok(())
    }

    pub fn delete(&self, device_id: &str) -> Result<()> {
        self.crypto_mgr.remove_key(device_id);
        self.take_pending_conn(device_id);
        if !self.store.remove_device(device_id) {
            return Err(ServerError::DeviceNotFound(device_id.to_string()));
        }
        Ok(())
    }

    /// Update editable device fields: name, encryption toggle, IP whitelist.
    /// Empty/whitespace `name` is ignored; an `enc_enabled` change is
    /// accepted but does not regenerate the key (call `RegenerateEncKey`
    /// for that). `ip_whitelist` is replaced wholesale when `Some`.
    pub fn update_config(
        &self,
        device_id: &str,
        name: Option<String>,
        enc_enabled: Option<bool>,
        ip_whitelist: Option<Vec<String>>,
    ) -> Result<DeviceState> {
        let updated = self.store.update_device(device_id, |d| {
            if let Some(n) = name.as_ref() {
                if !n.trim().is_empty() {
                    d.name = n.trim().to_string();
                }
            }
            if let Some(e) = enc_enabled {
                d.enc_enabled = e;
            }
            if let Some(list) = ip_whitelist {
                d.ip_whitelist = list;
            }
        });
        if !updated {
            return Err(ServerError::DeviceNotFound(device_id.to_string()));
        }
        self.store
            .get_device(device_id)
            .ok_or_else(|| ServerError::DeviceNotFound(device_id.to_string()))
    }

    /// Replace the device's per-device AES key. Returns the freshly
    /// generated key (hex) so the caller can pass it to a follow-up
    /// `register_update` push if needed. Encrypted delivery via ECDH is
    /// not applied here — the API endpoint should use the registration
    /// path for that.
    pub fn regenerate_enc_key(&self, device_id: &str) -> Result<[u8; 32]> {
        let exists = self.store.get_device(device_id).is_some();
        if !exists {
            return Err(ServerError::DeviceNotFound(device_id.to_string()));
        }
        let new_key = identity::generate_enc_key();
        self.crypto_mgr
            .set_key(device_id, &new_key)
            .map_err(ServerError::from)?;
        self.store.update_device(device_id, |d| {
            d.enc_key = hex::encode(new_key);
            d.enc_enabled = true;
        });
        Ok(new_key)
    }

    /// Replace the device's IP whitelist.
    pub fn set_ip_whitelist(
        &self,
        device_id: &str,
        list: Vec<String>,
    ) -> Result<DeviceState> {
        let updated = self.store.update_device(device_id, |d| {
            d.ip_whitelist = list;
        });
        if !updated {
            return Err(ServerError::DeviceNotFound(device_id.to_string()));
        }
        self.store
            .get_device(device_id)
            .ok_or_else(|| ServerError::DeviceNotFound(device_id.to_string()))
    }

    pub fn get_ip_whitelist(&self, device_id: &str) -> Result<Vec<String>> {
        self.store
            .get_device(device_id)
            .map(|d| d.ip_whitelist)
            .ok_or_else(|| ServerError::DeviceNotFound(device_id.to_string()))
    }

    // ---------- pending connections ----------

    pub fn add_pending_conn(&self, device_id: String, tx: mpsc::UnboundedSender<ServerOutMsg>, remote_ip: String) {
        let old = self.pending_conns.write().insert(
            device_id.clone(),
            PendingConn {
                tx: tx.clone(),
                remote_ip,
            },
        );
        if let Some(old) = old {
            // best-effort: signal close to previous socket
            let _ = old.tx.send(ServerOutMsg::CLOSE);
        }
    }

    pub fn take_pending_conn(&self, device_id: &str) -> Option<PendingConn> {
        self.pending_conns.write().remove(device_id)
    }

    /// Remove the pending slot only if the stored sender still matches the
    /// caller's sender. Used during connection teardown so an old socket
    /// cannot evict a freshly-reconnected socket that already replaced it.
    pub fn remove_self_pending(
        &self,
        device_id: &str,
        tx: &mpsc::UnboundedSender<ServerOutMsg>,
    ) -> bool {
        let mut guard = self.pending_conns.write();
        if let Some(existing) = guard.get(device_id) {
            if existing.tx.same_channel(tx) {
                guard.remove(device_id);
                return true;
            }
        }
        false
    }

    pub fn pending_conn(&self, device_id: &str) -> Option<PendingConn> {
        self.pending_conns.read().get(device_id).map(|p| PendingConn {
            tx: p.tx.clone(),
            remote_ip: p.remote_ip.clone(),
        })
    }
}

// ---------- helpers ----------

fn validate_sign_pubkey_hex(hex_str: &str) -> Result<()> {
    let bytes = hex::decode(hex_str).map_err(ServerError::from)?;
    if bytes.len() != ED25519_PUBKEY_SIZE {
        return Err(ServerError::Internal(format!(
            "invalid device sign pubkey size: {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn validate_dh_pubkey_hex(hex_str: &str) -> Result<()> {
    if hex_str.is_empty() {
        return Ok(());
    }
    let bytes = hex::decode(hex_str).map_err(ServerError::from)?;
    if bytes.len() != 32 {
        return Err(ServerError::Internal(format!(
            "invalid device dh pubkey size: {}",
            bytes.len()
        )));
    }
    Ok(())
}

impl ServerOutMsg {
    /// Sentinel that signals the connection task to shut down the socket.
    pub const CLOSE: ServerOutMsg = ServerOutMsg::Text(String::new());
}

impl DeviceState {
    pub fn status_str(&self) -> &'static str {
        match self.status {
            DeviceStatus::Pending => "pending",
            DeviceStatus::Authorized => "authorized",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_rs_common::identity;

    fn make_keys() -> (String, String) {
        let (vk, _sk) = identity::generate_sign_keypair();
        let (_dh_priv, dh_pub) = identity::generate_dh_keypair();
        (identity::encode_verifying_key(&vk), identity::encode_dh_public_key(&dh_pub))
    }

    fn store() -> Arc<StateStore> {
        Arc::new(StateStore::new_in_memory())
    }

    #[test]
    fn register_new_creates_pending_device() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr
            .register_new(&sign_pk, &dh_pk, "host", "linux", "10.0.0.1")
            .unwrap();
        assert_eq!(d.status, DeviceStatus::Pending);
        assert!(d.id.starts_with("client-"));
    }

    #[test]
    fn register_new_reuses_existing_pending() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let a = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();
        let b = mgr.register_new(&sign_pk, &dh_pk, "h2", "linux", "ip").unwrap();
        assert_eq!(a.id, b.id, "same pubkey should reuse client_id");
    }

    #[test]
    fn register_rejects_bad_sign_pubkey() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (_sign_pk, dh_pk) = make_keys();
        let err = mgr.register_new("abcd", &dh_pk, "h", "linux", "ip").unwrap_err();
        assert!(format!("{err}").contains("invalid device sign pubkey size"));
    }

    #[test]
    fn register_rejects_bad_dh_pubkey() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, _dh_pk) = make_keys();
        let err = mgr.register_new(&sign_pk, "abcd", "h", "linux", "ip").unwrap_err();
        assert!(format!("{err}").contains("invalid device dh pubkey size"));
    }

    #[test]
    fn approve_generates_enc_key_and_authorized() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();

        let (updated, enc_hex, srv_dh) = mgr.approve(&d.id).unwrap();
        assert_eq!(updated.status, DeviceStatus::Authorized);
        assert!(updated.enc_enabled);
        assert!(!updated.enc_key.is_empty());
        assert!(!enc_hex.is_empty());
        assert!(!srv_dh.is_empty());
        assert!(updated.approved_at.is_some());
    }

    #[test]
    fn approve_rejects_already_authorized() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();
        mgr.approve(&d.id).unwrap();
        let err = mgr.approve(&d.id).unwrap_err();
        assert!(matches!(err, ServerError::DeviceNotPending(_)));
    }

    #[test]
    fn approve_rejects_missing_dh_pubkey() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, _dh_pk) = make_keys();
        // empty dh pubkey
        let d = mgr.register_new(&sign_pk, "", "h", "linux", "ip").unwrap();
        let err = mgr.approve(&d.id).unwrap_err();
        assert!(matches!(err, ServerError::DeviceMissingDhPubkey));
    }

    #[test]
    fn reauth_succeeds_with_valid_signature() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();
        mgr.approve(&d.id).unwrap();

        let (vk, sk) = identity::generate_sign_keypair();
        // we registered with a different keypair; replace it for the test
        mgr.store.update_device(&d.id, |dev| {
            dev.device_sign_pubkey = identity::encode_verifying_key(&vk);
        });
        let now = chrono::Utc::now().timestamp();
        let sig = identity::sign_timestamp(&sk, &d.id, now);
        let sig_hex = hex::encode(sig.to_bytes());

        let got = mgr.reauth(&d.id, &identity::encode_verifying_key(&vk), now, &sig_hex).unwrap();
        assert_eq!(got.id, d.id);
    }

    #[test]
    fn reauth_rejects_wrong_signature() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();
        mgr.approve(&d.id).unwrap();

        let (_vk, sk) = identity::generate_sign_keypair();
        let now = chrono::Utc::now().timestamp();
        let sig = identity::sign_timestamp(&sk, &d.id, now);
        let sig_hex = hex::encode(sig.to_bytes());

        let err = mgr
            .reauth(&d.id, &sign_pk, now, &sig_hex)
            .unwrap_err();
        assert!(err.reason.contains("signature") || err.reason.contains("public key"));
    }

    #[test]
    fn reauth_rejects_unknown_device() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, _dh_pk) = make_keys();
        let err = mgr.reauth("client-ghost", &sign_pk, 0, "00").unwrap_err();
        assert!(err.reason.contains("not found"));
    }

    #[test]
    fn deny_removes_pending() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();
        mgr.deny(&d.id).unwrap();
        assert!(mgr.store.get_device(&d.id).is_none());
    }

    #[test]
    fn delete_clears_crypto_and_state() {
        let mgr = DeviceManager::new(store(), Arc::new(CryptoManager::new()));
        let (sign_pk, dh_pk) = make_keys();
        let d = mgr.register_new(&sign_pk, &dh_pk, "h", "linux", "ip").unwrap();
        mgr.approve(&d.id).unwrap();
        assert!(mgr.crypto_mgr.has_key(&d.id));
        mgr.delete(&d.id).unwrap();
        assert!(!mgr.crypto_mgr.has_key(&d.id));
        assert!(mgr.store.get_device(&d.id).is_none());
    }
}
