use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommonError {
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("AES cipher init failed: {0}")]
    Aes(String),

    #[error("GCM init failed: {0}")]
    Gcm(String),

    #[error("X25519 ECDH failed: {0}")]
    X25519(String),

    #[error("HKDF derive failed: {0}")]
    Hkdf(String),

    #[error("ed25519 sign failed: {0}")]
    Ed25519Sign(String),

    #[error("ed25519 verify failed: {0}")]
    Ed25519Verify(String),

    #[error("generate nonce failed: {0}")]
    Nonce(String),

    #[error("encrypt failed: {0}")]
    Encrypt(String),

    #[error("decrypt failed: {0}")]
    Decrypt(String),

    #[error("key must be 32 bytes, got {0}")]
    InvalidKeySize(usize),

    #[error("public key invalid size: {0}")]
    InvalidPublicKeySize(usize),

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    #[error("encryption key not found for client: {0}")]
    KeyNotFound(String),

    #[error("ciphertext too short: {got} bytes (min {min})")]
    CiphertextTooShort { got: usize, min: usize },

    #[error("tunnel_id too long: {0}")]
    TunnelIdTooLong(usize),

    #[error("conn_id too long: {0}")]
    ConnIdTooLong(usize),

    #[error("binary tunnel frame too short: {0} bytes")]
    FrameTooShort(usize),

    #[error("unsupported binary tunnel frame version: {0}")]
    FrameVersion(u8),

    #[error("unsupported binary tunnel frame flags: {0}")]
    FrameFlags(u8),

    #[error("invalid binary tunnel frame tunnel_id length: {0}")]
    FrameTunnelIdLen(usize),

    #[error("invalid binary tunnel frame conn_id length: {0}")]
    FrameConnIdLen(usize),

    #[error("invalid binary tunnel frame data length: got {got}, expected {expected}")]
    FrameDataLen { got: u32, expected: usize },

    #[error("invalid JSON: multiple values")]
    JsonMultipleValues,

    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto context is nil")]
    CryptoContextNil,

    #[error("invalid UTF-8 in frame: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

pub type Result<T> = std::result::Result<T, CommonError>;
