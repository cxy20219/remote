use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{CommonError, Result};

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

/// AES-256-GCM context for a single device's tunnel data.
///
/// Wire format produced by `encrypt`: `[nonce (12 bytes) | ciphertext + tag]`,
/// identical to Go's `CryptoContext.EncryptBytes` and consumed by `decrypt`.
#[derive(Clone)]
pub struct CryptoContext {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for CryptoContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoContext").finish_non_exhaustive()
    }
}

impl CryptoContext {
    pub fn from_key(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(CommonError::InvalidKeySize(key.len()));
        }
        let cipher =
            Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        // Per-frame nonce from the OS CSPRNG. See `CryptoManager::encrypt`
        // for the rationale; the same property holds here.
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CommonError::Encrypt(e.to_string()))?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(CommonError::CiphertextTooShort {
                got: ciphertext.len(),
                min: NONCE_SIZE,
            });
        }
        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| CommonError::Decrypt(e.to_string()))
    }
}

/// Per-client `CryptoContext` table. Lock-free reads via `DashMap`.
pub struct CryptoManager {
    keys: DashMap<String, Arc<CryptoContext>>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
        }
    }

    pub fn set_key(&self, client_id: &str, key: &[u8]) -> Result<()> {
        let ctx = CryptoContext::from_key(key)?;
        self.keys.insert(client_id.to_string(), Arc::new(ctx));
        Ok(())
    }

    pub fn remove_key(&self, client_id: &str) {
        self.keys.remove(client_id);
    }

    pub fn has_key(&self, client_id: &str) -> bool {
        self.keys.contains_key(client_id)
    }

    pub fn encrypt(&self, client_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ctx = self
            .keys
            .get(client_id)
            .ok_or_else(|| CommonError::KeyNotFound(client_id.to_string()))?;
        ctx.encrypt(plaintext)
    }

    pub fn decrypt(&self, client_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ctx = self
            .keys
            .get(client_id)
            .ok_or_else(|| CommonError::KeyNotFound(client_id.to_string()))?;
        ctx.decrypt(ciphertext)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn roundtrip() {
        let key = rand_key();
        let ctx = CryptoContext::from_key(&key).unwrap();
        let plaintext = b"hello tunnel data";
        let ciphertext = ctx.encrypt(plaintext).unwrap();
        let out = ctx.decrypt(&ciphertext).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts_per_call() {
        let key = rand_key();
        let ctx = CryptoContext::from_key(&key).unwrap();
        let a = ctx.encrypt(b"same").unwrap();
        let b = ctx.encrypt(b"same").unwrap();
        assert_ne!(a, b, "nonce must randomize output");
    }

    #[test]
    fn rejects_wrong_key_size() {
        let err = CryptoContext::from_key(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, CommonError::InvalidKeySize(16)));
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = rand_key();
        let ctx = CryptoContext::from_key(&key).unwrap();
        let mut ct = ctx.encrypt(b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        let err = ctx.decrypt(&ct).unwrap_err();
        assert!(matches!(err, CommonError::Decrypt(_)), "got {err:?}");
    }

    #[test]
    fn decrypt_rejects_short_ciphertext() {
        let key = rand_key();
        let ctx = CryptoContext::from_key(&key).unwrap();
        let err = ctx.decrypt(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, CommonError::CiphertextTooShort { got: 5, min: 12 }));
    }

    #[test]
    fn manager_isolates_clients() {
        let mgr = CryptoManager::new();
        let key_a = rand_key();
        let key_b = rand_key();
        mgr.set_key("client-a", &key_a).unwrap();
        mgr.set_key("client-b", &key_b).unwrap();

        let ct_a = mgr.encrypt("client-a", b"x").unwrap();
        let pt = mgr.decrypt("client-a", &ct_a).unwrap();
        assert_eq!(pt, b"x");

        // cross-decrypt with wrong key must fail
        let err = mgr.decrypt("client-b", &ct_a).unwrap_err();
        assert!(matches!(err, CommonError::Decrypt(_)), "got {err:?}");
    }

    #[test]
    fn manager_rejects_unknown_client() {
        let mgr = CryptoManager::new();
        let err = mgr.encrypt("ghost", b"x").unwrap_err();
        assert!(matches!(err, CommonError::KeyNotFound(ref s) if s == "ghost"));
    }

    #[test]
    fn manager_replace_key() {
        let mgr = CryptoManager::new();
        let k1 = rand_key();
        let k2 = rand_key();
        mgr.set_key("c", &k1).unwrap();
        mgr.set_key("c", &k2).unwrap();
        let ct1 = mgr.encrypt("c", b"x").unwrap();
        // decrypt with new key works
        assert_eq!(mgr.decrypt("c", &ct1).unwrap(), b"x");
    }

    #[test]
    fn manager_remove_key() {
        let mgr = CryptoManager::new();
        let key = rand_key();
        mgr.set_key("c", &key).unwrap();
        assert!(mgr.has_key("c"));
        mgr.remove_key("c");
        assert!(!mgr.has_key("c"));
        let err = mgr.encrypt("c", b"x").unwrap_err();
        assert!(matches!(err, CommonError::KeyNotFound(_)));
    }
}
