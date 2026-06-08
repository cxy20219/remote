use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::codec::decode_strict_json;
use crate::error::Result;

// ---------- Envelope ----------
//
// Mirrors Go's `Message` struct: a `type` discriminator with an opaque
// `payload` blob that the caller decodes into a strongly typed struct that
// opts into `#[serde(deny_unknown_fields)]`.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WsMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

impl WsMessage {
    pub fn new(msg_type: impl Into<String>) -> Self {
        Self {
            msg_type: msg_type.into(),
            payload: None,
        }
    }

    pub fn with_payload(msg_type: impl Into<String>, payload: Value) -> Self {
        Self {
            msg_type: msg_type.into(),
            payload: Some(payload),
        }
    }
}

/// Decode the wire envelope. Rejects unknown fields at the envelope level
/// (e.g. an extra `foo` field next to `type`) and trailing JSON values.
pub fn decode_envelope(data: &[u8]) -> Result<WsMessage> {
    decode_strict_json(data)
}

/// Decode a strongly typed payload. The target type must opt into
/// `#[serde(deny_unknown_fields)]` to match Go's `DisallowUnknownFields`.
pub fn decode_payload<T>(value: Value) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    Ok(serde_json::from_value(value)?)
}

// ---------- Control message payloads ----------
//
// Field names and `omitempty` semantics are pinned to the Go types in
// `internal/common/message.go` so the wire format is byte-identical.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterPayload {
    #[serde(default)]
    pub reauth: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub device_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_dh_pubkey: Option<String>,
    pub hostname: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterPendingPayload {
    pub client_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterOkPayload {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_key_encrypted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_dh_pubkey: Option<String>,
    pub enc_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterFailPayload {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegisterUpdatePayload {
    pub update_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_key_encrypted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_dh_pubkey: Option<String>,
    pub enc_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelOpenPayload {
    pub tunnel_id: String,
    pub local_addr: String,
    pub local_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelOpenAckPayload {
    pub tunnel_id: String,
    pub public_port: u16,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelClosePayload {
    pub tunnel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelErrorPayload {
    pub tunnel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_id: Option<String>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelUpdatePayload {
    pub tunnel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelUpdateAckPayload {
    pub tunnel_id: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceDeletedPayload {
    pub reason: String,
}

// ---------- Helpers for building common envelopes ----------

pub fn ping_message() -> WsMessage {
    WsMessage::new("ping")
}

pub fn pong_message() -> WsMessage {
    WsMessage::new("pong")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_rejects_unknown_field() {
        let data = br#"{"type":"ping","extra":1}"#;
        let err = decode_envelope(data).unwrap_err();
        assert!(matches!(err, crate::CommonError::Json(_)), "got {err:?}");
    }

    #[test]
    fn envelope_decodes_register() {
        let data = br#"{"type":"register","payload":{"device_pubkey":"abcd","hostname":"h","os":"linux"}}"#;
        let env = decode_envelope(data).unwrap();
        assert_eq!(env.msg_type, "register");
        let p: RegisterPayload = decode_payload(env.payload.unwrap()).unwrap();
        assert_eq!(p.device_pubkey, "abcd");
        assert_eq!(p.hostname, "h");
        assert!(!p.reauth);
    }

    #[test]
    fn register_payload_rejects_unknown_field() {
        let data = br#"{"type":"register","payload":{"device_pubkey":"abcd","hostname":"h","os":"linux","foo":"bar"}}"#;
        let env = decode_envelope(data).unwrap();
        let err = decode_payload::<RegisterPayload>(env.payload.unwrap()).unwrap_err();
        assert!(matches!(err, crate::CommonError::Json(_)), "got {err:?}");
    }

    #[test]
    fn register_reauth_carries_signature_and_timestamp() {
        let v = json!({
            "reauth": true,
            "client_id": "client-1",
            "device_pubkey": "abcd",
            "device_dh_pubkey": "ef01",
            "hostname": "h",
            "os": "linux",
            "timestamp": 1_700_000_000_i64,
            "signature": "deadbeef"
        });
        let p: RegisterPayload = decode_payload(v).unwrap();
        assert!(p.reauth);
        assert_eq!(p.client_id.as_deref(), Some("client-1"));
        assert_eq!(p.timestamp, Some(1_700_000_000));
        assert_eq!(p.signature.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn register_ok_roundtrip() {
        let p = RegisterOkPayload {
            client_id: "c-1".into(),
            enc_key_encrypted: Some("aabb".into()),
            server_dh_pubkey: Some("1122".into()),
            enc_enabled: true,
        };
        let v = serde_json::to_value(&p).unwrap();
        let back: RegisterOkPayload = decode_payload(v).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn tunnel_open_payload_rejects_wrong_type() {
        let v = json!({
            "tunnel_id": "t",
            "local_addr": "127.0.0.1",
            "local_port": "twentytwo", // wrong type
            "protocol": "tcp"
        });
        let err = decode_payload::<TunnelOpenPayload>(v).unwrap_err();
        assert!(matches!(err, crate::CommonError::Json(_)));
    }

    #[test]
    fn ping_envelope_has_no_payload_field() {
        let env = ping_message();
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(json, r#"{"type":"ping"}"#);
    }

    #[test]
    fn device_deleted_payload_required_reason() {
        let v = json!({});
        let err = decode_payload::<DeviceDeletedPayload>(v).unwrap_err();
        assert!(matches!(err, crate::CommonError::Json(_)));
    }

    #[test]
    fn register_update_with_omitted_enc_key_works() {
        let v = json!({
            "update_type": "enc_disabled",
            "enc_enabled": false
        });
        let p: RegisterUpdatePayload = decode_payload(v).unwrap();
        assert_eq!(p.update_type, "enc_disabled");
        assert!(!p.enc_enabled);
        assert!(p.enc_key_encrypted.is_none());
        assert!(p.server_dh_pubkey.is_none());
    }
}
