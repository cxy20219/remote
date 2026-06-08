//! Shared protocol, crypto, and codec primitives for the tunnel-rs server and
//! agent. Protocol is wire-compatible with go-remote so the Rust server can
//! interoperate with the Go agent (and vice versa) during a gradual rollout.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod codec;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod identity;
pub mod message;

pub use crypto::CryptoManager;
pub use error::{CommonError, Result};
pub use identity::{
    decode_bytes, decode_dh_public_key, decode_signing_key, decode_verifying_key,
    decrypt_key_with_shared_secret, dh_shared_secret, encode_bytes, encode_dh_public_key,
    encode_signing_key, encode_verifying_key, encrypt_key_with_shared_secret,
    generate_dh_keypair, generate_enc_key, generate_sign_keypair, is_timestamp_valid,
    sign_timestamp, verify_timestamp, Signature, VerifyingKey, ED25519_PUBKEY_SIZE,
};
pub use message::{
    decode_envelope, decode_payload, ping_message, pong_message, RegisterFailPayload,
    RegisterOkPayload, RegisterPayload, RegisterPendingPayload, RegisterUpdatePayload,
    TunnelClosePayload, TunnelErrorPayload, TunnelOpenAckPayload, TunnelOpenPayload,
    TunnelUpdateAckPayload, TunnelUpdatePayload, WsMessage,
};
pub use frame::{decode as decode_frame, encode as encode_frame, BinaryTunnelData};

pub const TUNNEL_CHUNK_SIZE: usize = 256 * 1024;
pub const WS_BUFFER_SIZE: usize = 128 * 1024;
pub const MAX_WS_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

