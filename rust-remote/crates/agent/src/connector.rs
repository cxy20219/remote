//! WebSocket connector and initial handshake.
//!
//! The connector owns the underlying tungstenite stream and exposes
//! `register_new` / `register_reauth` helpers that send the first message
//! and synchronously wait for the server's `register_*` response. The
//! caller takes ownership of the live socket afterwards.
//!
//! TLS is delegated to `rustls` via the `rustls-tls-webpki-roots` feature
//! of `tokio-tungstenite`. When `tls_ca` is set, the bundled CA roots are
//! augmented with the PEM file's certificates. `--insecure-skip-verify`
//! disables server certificate validation entirely (development only).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_pki_types::{CertificateDer, ServerName};
use serde_json::Value;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::info;
use tunnel_rs_common::{
    decode_envelope, message::RegisterPayload, message::WsMessage, sign_timestamp,
};

use crate::identity::AgentIdentity;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("websocket error: {0}")]
    Ws(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialise: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("handshake timeout")]
    HandshakeTimeout,
    #[error("server returned an unexpected message: {0}")]
    Unexpected(String),
    #[error("invalid identity: {0}")]
    Identity(String),
    #[error("invalid TLS CA bundle: {0}")]
    TlsCa(String),
    #[error("TLS host resolution: {0}")]
    TlsHost(String),
}

// `tungstenite::Error` is a large enum (TLS / IO / capacity / protocol) and
// would inflate the `Result` size if held inline; the WS error is converted
// to a string at the boundary instead.
pub type Result<T> = std::result::Result<T, ConnectorError>;

pub type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

pub struct Connector {
    server: String,
    tls: bool,
    tls_ca: Option<PathBuf>,
    insecure_skip_verify: bool,
}

impl Connector {
    pub fn new(server: impl Into<String>, tls: bool) -> Self {
        Self {
            server: server.into(),
            tls,
            tls_ca: None,
            insecure_skip_verify: false,
        }
    }

    /// Builder-style setter for a custom CA bundle (PEM file).
    pub fn with_tls_ca(mut self, path: Option<PathBuf>) -> Self {
        self.tls_ca = path;
        self
    }

    /// Builder-style setter for the dev-only "skip verify" flag.
    pub fn with_insecure_skip_verify(mut self, value: bool) -> Self {
        self.insecure_skip_verify = value;
        self
    }

    pub fn scheme(&self) -> &'static str {
        if self.tls { "wss" } else { "ws" }
    }

    pub fn url(&self) -> String {
        format!("{}://{}/ws", self.scheme(), self.server)
    }

    pub async fn connect(&self) -> Result<WsStream> {
        let url = self.url();
        if !self.tls {
            info!(url = %url, "connecting to server (plain ws)");
            let (ws, _resp) = tokio_tungstenite::connect_async(url.as_str())
                .await
                .map_err(|e| ConnectorError::Ws(e.to_string()))?;
            return Ok(ws);
        }
        let config = build_rustls_config(self.tls_ca.as_deref(), self.insecure_skip_verify)?;
        info!(
            url = %url,
            tls_ca = ?self.tls_ca,
            insecure = self.insecure_skip_verify,
            "connecting to server (rustls wss)"
        );
        let connector = tokio_tungstenite::Connector::Rustls(Arc::new(config));
        let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
            url.as_str(),
            None,
            false,
            Some(connector),
        )
        .await
        .map_err(|e| ConnectorError::Ws(e.to_string()))?;
        Ok(ws)
    }
}

/// Build a rustls `ClientConfig`. When `tls_ca` is set, the certs in the
/// PEM file are appended to the webpki roots. `insecure_skip_verify`
/// short-circuits to a verifier that accepts any certificate.
fn build_rustls_config(
    tls_ca: Option<&Path>,
    insecure_skip_verify: bool,
) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = tls_ca {
        let data = std::fs::read(path)
            .map_err(|e| ConnectorError::TlsCa(format!("read {}: {e}", path.display())))?;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ConnectorError::TlsCa(format!("parse {}: {e}", path.display())))?;
        if certs.is_empty() {
            return Err(ConnectorError::TlsCa(format!(
                "{} contained no PEM certificates",
                path.display()
            )));
        }
        let (added, ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(ConnectorError::TlsCa(format!(
                "{}: no usable certs (ignored {})",
                path.display(),
                ignored
            )));
        }
    }

    if insecure_skip_verify {
        return Ok(ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
            .with_no_client_auth());
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// `ServerName` resolution that handles `host:port` strings by stripping
/// the port (rustls requires a bare DNS name / IP). Returns the resolved
/// `ServerName` plus the host portion that should be used to dial.
#[allow(dead_code)]
pub(crate) fn resolve_server_name(server: &str) -> Result<ServerName<'static>> {
    let host = server
        .split(':')
        .next()
        .unwrap_or(server)
        .trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(ConnectorError::TlsHost("empty host".into()));
    }
    ServerName::try_from(host)
        .map(|n| n.to_owned())
        .map_err(|e| ConnectorError::TlsHost(format!("{host}: {e}")))
}

/// Verifier that accepts any server certificate. Only used when
/// `--insecure-skip-verify` is passed; never in production.
#[derive(Debug)]
struct AcceptAnyVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub enum RegisterResponse {
    Pending { client_id: String },
    Ok {
        client_id: String,
        enc_key_encrypted: Option<String>,
        server_dh_pubkey: Option<String>,
        enc_enabled: bool,
    },
    Failed { reason: String },
}

/// Send `register` (reauth=false) and wait for the first `register_*`
/// response, then hand the live socket back to the caller.
pub async fn register_new(
    identity: &AgentIdentity,
    connector: &Connector,
    hostname: &str,
    os_name: &str,
) -> Result<(WsStream, RegisterResponse)> {
    let mut ws = connector.connect().await?;
    let payload = RegisterPayload {
        reauth: false,
        client_id: None,
        device_pubkey: identity.device_pubkey.clone(),
        device_dh_pubkey: Some(identity.device_dh_pubkey.clone()),
        hostname: hostname.to_string(),
        os: os_name.to_string(),
        timestamp: None,
        signature: None,
    };
    let envelope = WsMessage::with_payload("register", serde_json::to_value(&payload)?);
    ws.send(Message::Text(serde_json::to_string(&envelope)?))
        .await
        .map_err(|e| ConnectorError::Ws(e.to_string()))?;
    let resp = wait_for_register_response(&mut ws).await?;
    Ok((ws, resp))
}

pub async fn register_reauth(
    identity: &AgentIdentity,
    connector: &Connector,
    hostname: &str,
    os_name: &str,
) -> Result<(WsStream, RegisterResponse)> {
    let mut ws = connector.connect().await?;
    let client_id = identity
        .client_id
        .as_ref()
        .ok_or_else(|| ConnectorError::Identity("client_id missing for reauth".into()))?;
    let sk = identity
        .sign_privkey()
        .map_err(|e| ConnectorError::Identity(e.to_string()))?;
    let timestamp = chrono::Utc::now().timestamp();
    let sig = sign_timestamp(&sk, client_id, timestamp);
    let payload = RegisterPayload {
        reauth: true,
        client_id: Some(client_id.clone()),
        device_pubkey: identity.device_pubkey.clone(),
        device_dh_pubkey: Some(identity.device_dh_pubkey.clone()),
        hostname: hostname.to_string(),
        os: os_name.to_string(),
        timestamp: Some(timestamp),
        signature: Some(hex::encode(sig.to_bytes())),
    };
    let envelope = WsMessage::with_payload("register", serde_json::to_value(&payload)?);
    ws.send(Message::Text(serde_json::to_string(&envelope)?))
        .await
        .map_err(|e| ConnectorError::Ws(e.to_string()))?;
    let resp = wait_for_register_response(&mut ws).await?;
    Ok((ws, resp))
}

async fn wait_for_register_response(ws: &mut WsStream) -> Result<RegisterResponse> {
    loop {
    let frame = timeout(HANDSHAKE_TIMEOUT, ws.next())
        .await
        .map_err(|_| ConnectorError::HandshakeTimeout)?
        .ok_or(ConnectorError::HandshakeTimeout)?
        .map_err(|e| ConnectorError::Ws(e.to_string()))?;
        match frame {
            Message::Text(text) => {
                let env: WsMessage = decode_envelope(text.as_bytes())
                    .map_err(|e| ConnectorError::Unexpected(e.to_string()))?;
                match env.msg_type.as_str() {
                    "register_pending" => {
                        let payload: Value = env
                            .payload
                            .ok_or_else(|| ConnectorError::Unexpected("missing payload".into()))?;
                        return Ok(RegisterResponse::Pending {
                            client_id: payload["client_id"]
                                .as_str()
                                .ok_or_else(|| {
                                    ConnectorError::Unexpected("missing client_id".into())
                                })?
                                .to_string(),
                        });
                    }
                    "register_ok" => {
                        let payload: Value = env
                            .payload
                            .ok_or_else(|| ConnectorError::Unexpected("missing payload".into()))?;
                        return Ok(RegisterResponse::Ok {
                            client_id: payload["client_id"]
                                .as_str()
                                .ok_or_else(|| {
                                    ConnectorError::Unexpected("missing client_id".into())
                                })?
                                .to_string(),
                            enc_key_encrypted: payload["enc_key_encrypted"]
                                .as_str()
                                .map(String::from),
                            server_dh_pubkey: payload["server_dh_pubkey"]
                                .as_str()
                                .map(String::from),
                            enc_enabled: payload["enc_enabled"].as_bool().unwrap_or(false),
                        });
                    }
                    "register_fail" => {
                        let payload: Value = env
                            .payload
                            .ok_or_else(|| ConnectorError::Unexpected("missing payload".into()))?;
                        return Ok(RegisterResponse::Failed {
                            reason: payload["reason"]
                                .as_str()
                                .unwrap_or("unknown")
                                .to_string(),
                        });
                    }
                    "ping" => continue,
                    other => {
                        return Err(ConnectorError::Unexpected(format!(
                            "{other} during handshake"
                        )));
                    }
                }
            }
            Message::Binary(_) => continue,
            Message::Close(_) => {
                return Err(ConnectorError::Unexpected(
                    "server closed during handshake".into(),
                ));
            }
            _ => continue,
        }
    }
}
