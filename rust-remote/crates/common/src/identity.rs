use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
pub use ed25519_dalek::Signature;
pub use ed25519_dalek::Signer;
pub use ed25519_dalek::Verifier;
pub use ed25519_dalek::VerifyingKey;
#[allow(unused_imports)]
pub use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{CommonError, Result};

pub const ED25519_PUBKEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

const HKDF_INFO: &[u8] = b"goremote-enc-key-exchange-v1";
const SIGNING_KEY_SIZE: usize = 32;
const VERIFYING_KEY_SIZE: usize = 32;
const DH_KEY_SIZE: usize = 32;
const GCM_NONCE_SIZE: usize = 12;

// ---------- ed25519 signing keypair ----------

pub fn generate_sign_keypair() -> (VerifyingKey, SigningKey) {
    // ed25519-dalek 2.x removed `SigningKey::generate`; we draw 32 random
    // bytes and use `from_bytes` which is the documented replacement.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

pub fn encode_signing_key(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

pub fn decode_signing_key(hex_str: &str) -> Result<SigningKey> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != SIGNING_KEY_SIZE {
        return Err(CommonError::InvalidKeySize(bytes.len()));
    }
    let mut arr = [0u8; SIGNING_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

pub fn decode_verifying_key(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != VERIFYING_KEY_SIZE {
        return Err(CommonError::InvalidPublicKeySize(bytes.len()));
    }
    let mut arr = [0u8; VERIFYING_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| CommonError::Ed25519Verify(e.to_string()))
}

// ---------- X25519 ECDH ----------

pub fn generate_dh_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn encode_dh_public_key(key: &PublicKey) -> String {
    hex::encode(key.as_bytes())
}

pub fn decode_dh_public_key(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != DH_KEY_SIZE {
        return Err(CommonError::InvalidPublicKeySize(bytes.len()));
    }
    let mut arr = [0u8; DH_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

/// X25519 shared secret. Symmetric: `dh(a, B) == dh(b, A)`.
pub fn dh_shared_secret(priv_key: &StaticSecret, pub_key: &PublicKey) -> [u8; 32] {
    priv_key.diffie_hellman(pub_key).to_bytes()
}

// ---------- enc_key transport encryption ----------
//
// Used by the server when delivering the AES-256-GCM tunnel key to a freshly
// approved agent. The server generates an ephemeral X25519 keypair, computes
// the shared secret with the agent's pre-shared DH pubkey, runs HKDF-SHA256
// to derive a transport cipher, and ships `nonce || ciphertext` hex-encoded.

pub fn encrypt_key_with_shared_secret(plain_key: &[u8], shared_secret: &[u8]) -> Result<String> {
    // Wire-compat with Go's `EncryptKeyWithSharedSecret`:
    //   hkdf.New(sha256.New, shared, salt=HKDF_INFO, info=nil)
    // Rust's `hkdf` crate uses `Hkdf::new(salt, secret)` then `expand(info, ...)`.
    // We therefore pass HKDF_INFO as the *salt* and use an empty `info`.
    let mut derived = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_INFO), shared_secret)
        .expand(&[], &mut derived)
        .map_err(|e| CommonError::Hkdf(e.to_string()))?;

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&derived));
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ref = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ref, plain_key)
        .map_err(|e| CommonError::Encrypt(e.to_string()))?;

    let mut out = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    derived.zeroize();
    Ok(hex::encode(out))
}

pub fn decrypt_key_with_shared_secret(enc_hex: &str, shared_secret: &[u8]) -> Result<Vec<u8>> {
    let ciphertext = hex::decode(enc_hex)?;
    if ciphertext.len() < GCM_NONCE_SIZE {
        return Err(CommonError::CiphertextTooShort {
            got: ciphertext.len(),
            min: GCM_NONCE_SIZE,
        });
    }
    let (nonce, encrypted) = ciphertext.split_at(GCM_NONCE_SIZE);

    // Wire-compat with Go (see `encrypt_key_with_shared_secret`).
    let mut derived = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_INFO), shared_secret)
        .expand(&[], &mut derived)
        .map_err(|e| CommonError::Hkdf(e.to_string()))?;

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&derived));
    let nonce_ref = Nonce::from_slice(nonce);
    let plain = cipher
        .decrypt(nonce_ref, encrypted)
        .map_err(|e| CommonError::Decrypt(e.to_string()))?;

    derived.zeroize();
    Ok(plain)
}

// ---------- per-device AES tunnel key ----------

pub fn generate_enc_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

// ---------- timestamp-based challenge response ----------

pub fn sign_timestamp(priv_key: &SigningKey, client_id: &str, timestamp: i64) -> Signature {
    let msg = format!("{client_id}:{timestamp}");
    priv_key.sign(msg.as_bytes())
}

pub fn verify_timestamp(
    pub_key: &VerifyingKey,
    client_id: &str,
    timestamp: i64,
    signature: &Signature,
) -> bool {
    let msg = format!("{client_id}:{timestamp}");
    pub_key.verify(msg.as_bytes(), signature).is_ok()
}

pub fn is_timestamp_valid(timestamp: i64, max_drift_secs: i64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (now - timestamp).abs() <= max_drift_secs
}

// ---------- generic hex helpers (mirror Go's EncodeBytes/DecodeBytes) ----------

pub fn encode_bytes(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn decode_bytes(hex_str: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(hex_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_keypair_roundtrip() {
        let (vk, sk) = generate_sign_keypair();
        let encoded_sk = encode_signing_key(&sk);
        let encoded_vk = encode_verifying_key(&vk);
        let decoded_sk = decode_signing_key(&encoded_sk).unwrap();
        let decoded_vk = decode_verifying_key(&encoded_vk).unwrap();
        assert_eq!(sk.to_bytes(), decoded_sk.to_bytes());
        assert_eq!(vk.to_bytes(), decoded_vk.to_bytes());
    }

    #[test]
    fn sign_verify_timestamp() {
        let (_vk, sk) = generate_sign_keypair();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sig = sign_timestamp(&sk, "client-123", now);
        let (_, sk2) = generate_sign_keypair();
        let vk2 = sk2.verifying_key();
        // Different keypair must not validate the signature.
        assert!(!verify_timestamp(&vk2, "client-123", now, &sig));
    }

    #[test]
    fn sign_verify_rejects_wrong_client_id() {
        let (vk, sk) = generate_sign_keypair();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Sign for client-A, verify with client-B — must fail.
        let sig = sign_timestamp(&sk, "client-A", now);
        let valid = verify_timestamp(&vk, "client-B", now, &sig);
        assert!(!valid, "signature for client-A must not verify under client-B");
    }

    #[test]
    fn timestamp_validity_window() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(is_timestamp_valid(now, 300));
        assert!(is_timestamp_valid(now + 100, 300));
        assert!(!is_timestamp_valid(now + 600, 300));
        assert!(!is_timestamp_valid(now - 600, 300));
    }

    #[test]
    fn dh_shared_secret_is_symmetric() {
        let (a_priv, a_pub) = generate_dh_keypair();
        let (b_priv, b_pub) = generate_dh_keypair();
        let s1 = dh_shared_secret(&a_priv, &b_pub);
        let s2 = dh_shared_secret(&b_priv, &a_pub);
        assert_eq!(s1, s2);
    }

    #[test]
    fn dh_shared_secret_hex_roundtrip() {
        let (_a_priv, a_pub) = generate_dh_keypair();
        let encoded = encode_dh_public_key(&a_pub);
        let decoded = decode_dh_public_key(&encoded).unwrap();
        assert_eq!(a_pub.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn enc_key_transport_roundtrip() {
        let (server_priv, _server_pub) = generate_dh_keypair();
        let (_agent_priv, agent_pub) = generate_dh_keypair();
        let shared = dh_shared_secret(&server_priv, &agent_pub);
        let plain = generate_enc_key();

        let encrypted = encrypt_key_with_shared_secret(&plain, &shared).unwrap();
        let decrypted = decrypt_key_with_shared_secret(&encrypted, &shared).unwrap();
        assert_eq!(decrypted, plain.to_vec());
    }

    #[test]
    fn enc_key_transport_wrong_shared_secret_fails() {
        let (a_priv, _a_pub) = generate_dh_keypair();
        let (b_priv, _b_pub) = generate_dh_keypair();
        let (_c_priv, c_pub) = generate_dh_keypair();
        let shared_wrong = dh_shared_secret(&a_priv, &c_pub);
        let shared_correct = dh_shared_secret(&b_priv, &c_pub);

        let plain = generate_enc_key();
        let encrypted = encrypt_key_with_shared_secret(&plain, &shared_correct).unwrap();
        let err = decrypt_key_with_shared_secret(&encrypted, &shared_wrong).unwrap_err();
        assert!(matches!(err, CommonError::Decrypt(_)), "got {err:?}");
    }

    #[test]
    fn enc_key_transport_rejects_short_ciphertext() {
        let shared = [0u8; 32];
        // 2 bytes (decoded "aabb") is shorter than the 12-byte GCM nonce
        let err = decrypt_key_with_shared_secret("aabb", &shared).unwrap_err();
        assert!(
            matches!(err, CommonError::CiphertextTooShort { got: 2, min: 12 }),
            "got {err:?}"
        );
    }

    #[test]
    fn dh_decode_rejects_bad_size() {
        let err = decode_dh_public_key("aabb").unwrap_err();
        // "aabb" decodes to 2 bytes, not 32
        assert!(matches!(err, CommonError::InvalidPublicKeySize(2)));
    }

    #[test]
    fn sign_decode_rejects_bad_size() {
        let err = decode_signing_key("aabbcc").unwrap_err();
        assert!(matches!(err, CommonError::InvalidKeySize(3)));
    }

    #[test]
    fn verify_decode_rejects_bad_size() {
        let err = decode_verifying_key("aabbcc").unwrap_err();
        assert!(matches!(err, CommonError::InvalidPublicKeySize(3)));
    }
}
