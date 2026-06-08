//! WebSocket upgrade + connection lifecycle.
//!
//! The connection runs a single task that drives a `WebSocket` split into a
//! writer (forwarding `mpsc::UnboundedSender<ServerOutMsg>` events into the
//! socket) and a reader (parsing control frames). Approve/deny happen
//! out-of-band: the `DeviceManager` stores a clone of the writer for each
//! pending device and pushes the encrypted `register_ok` down the channel.
//!
//! Phase 3 adds tunnel handling: `tunnel_open` / `tunnel_close` text frames
//! and `tunnel_data_bin` binary frames. Tunnel data is decrypted with the
//! device's per-device AES key and forwarded to the matching external
//! connection. Encrypted payloads going the other way (ext conn → agent) are
//! emitted by the tunnel manager itself.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tunnel_rs_common::{
    decode_envelope, decode_frame, message::RegisterPayload, message::TunnelClosePayload,
    message::TunnelOpenAckPayload, message::TunnelOpenPayload, message::WsMessage,
    MAX_WS_MESSAGE_SIZE,
};

use crate::device_mgr::{DeviceManager, ServerOutMsg};
use crate::state::{AppState, DeviceState, DeviceStatus};
use crate::tunnel::TunnelExposure;

/// axum handler that upgrades the HTTP request to a WebSocket and hands the
/// socket to [`handle_socket`].
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if !state.ws_limiter.allow(remote.ip()) {
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
            .into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, remote, state))
}

async fn handle_socket(socket: WebSocket, remote: SocketAddr, state: Arc<AppState>) {
    let remote_ip = remote.ip().to_string();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerOutMsg>();

    // Writer task: drain mpsc and push to the socket. Empty text is the close
    // sentinel — `DeviceManager` uses it to evict stale pending connections.
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let axum_msg = match msg {
                ServerOutMsg::Text(s) if s.is_empty() => break,
                ServerOutMsg::Text(s) => Message::Text(s),
                ServerOutMsg::Binary(b) => Message::Binary(b),
            };
            if ws_tx.send(axum_msg).await.is_err() {
                break;
            }
        }
    });

    // Reader: one big loop covering the initial register handshake and the
    // pending/authorized working state.
    let mut session = ConnectionSession::new(state.clone(), out_tx.clone(), remote_ip);

    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_WS_MESSAGE_SIZE {
                    warn!(
                        size = text.len(),
                        limit = MAX_WS_MESSAGE_SIZE,
                        "ws text frame exceeds MAX_WS_MESSAGE_SIZE, closing"
                    );
                    break;
                }
                if let Err(e) = session.handle_text(&text).await {
                    debug!(error = %e, "closing ws after handler error");
                    break;
                }
            }
            Ok(Message::Binary(bin)) => {
                if bin.len() > MAX_WS_MESSAGE_SIZE {
                    warn!(
                        size = bin.len(),
                        limit = MAX_WS_MESSAGE_SIZE,
                        "ws binary frame exceeds MAX_WS_MESSAGE_SIZE, closing"
                    );
                    break;
                }
                if let Err(e) = session.handle_binary(&bin).await {
                    debug!(error = %e, "binary frame error");
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            Err(e) => {
                debug!(error = %e, "ws read error");
                break;
            }
        }
    }

    // Cleanup: only the connection that currently owns the pending slot
    // should remove it. Authorised devices are owned by
    // `authorized_senders` — remove on disconnect.
    session.cleanup();
    let _ = out_tx.send(ServerOutMsg::CLOSE);
    let _ = writer.await;
}

/// Per-connection state machine. Tracks the device under negotiation and the
/// channel used by background tasks (approvals, tunnel forwarding) to push
/// messages back to the agent.
struct ConnectionSession {
    state: Arc<AppState>,
    tx: mpsc::UnboundedSender<ServerOutMsg>,
    remote_ip: String,
    device: Option<DeviceState>,
    is_pending: bool,
    is_authorized: bool,
}

impl ConnectionSession {
    fn new(state: Arc<AppState>, tx: mpsc::UnboundedSender<ServerOutMsg>, remote_ip: String) -> Self {
        Self {
            state,
            tx,
            remote_ip,
            device: None,
            is_pending: false,
            is_authorized: false,
        }
    }

    fn send_text(&self, msg_type: &str, payload: serde_json::Value) {
        let json = match serde_json::to_string(&WsMessage::with_payload(msg_type, payload)) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialise outbound message");
                return;
            }
        };
        let _ = self.tx.send(ServerOutMsg::Text(json));
    }

    fn send_pong(&self) {
        if let Ok(s) = serde_json::to_string(&WsMessage::new("pong")) {
            let _ = self.tx.send(ServerOutMsg::Text(s));
        }
    }

    async fn handle_text(&mut self, raw: &str) -> Result<(), String> {
        let envelope = decode_envelope(raw.as_bytes()).map_err(|e| e.to_string())?;
        match envelope.msg_type.as_str() {
            "register" => self.handle_register(envelope.payload).await,
            "ping" => {
                self.send_pong();
                // Pending devices send pings while waiting. Use the chance
                // to detect the authorized transition (admin clicked approve
                // while the connection was idle).
                if self.is_pending {
                    self.maybe_promote_pending_to_authorized();
                }
                Ok(())
            }
            "tunnel_open" => self.handle_tunnel_open(envelope.payload).await,
            "tunnel_close" => self.handle_tunnel_close(envelope.payload).await,
            "tunnel_update" | "tunnel_update_ack" => {
                // Phase 4 will implement; ignore for now.
                Ok(())
            }
            other => {
                debug!(msg_type = %other, "ignoring unknown message");
                Ok(())
            }
        }
    }

    async fn handle_binary(&mut self, data: &[u8]) -> Result<(), String> {
        if !self.is_authorized {
            debug!("binary frame before authorization, dropping");
            return Ok(());
        }
        let frame = decode_frame(data).map_err(|e| e.to_string())?;
        let device_id = self
            .device
            .as_ref()
            .map(|d| d.id.clone())
            .ok_or_else(|| "no device for binary frame".to_string())?;
        let plaintext = self
            .state
            .crypto_mgr
            .decrypt(&device_id, &frame.data)
            .map_err(|e| e.to_string())?;
        self.state
            .tunnel_mgr
            .dispatch_from_agent(&frame.tunnel_id, &frame.conn_id, &plaintext, frame.is_eof)
            .await;
        Ok(())
    }

    async fn handle_register(&mut self, payload: Option<serde_json::Value>) -> Result<(), String> {
        let payload = payload.unwrap_or(serde_json::Value::Null);
        let p: RegisterPayload = serde_json::from_value(payload).map_err(|e| e.to_string())?;

        if p.reauth {
            if let Some(ref cid) = p.client_id {
                match self.state.device_mgr.reauth(
                    cid,
                    &p.device_pubkey,
                    p.timestamp.unwrap_or(0),
                    p.signature.as_deref().unwrap_or(""),
                ) {
                    Ok(device) => {
                        self.device = Some(device.clone());
                        self.is_pending = false;
                        self.is_authorized = true;
                        self.register_authorized_sender();
                        self.send_text(
                            "register_ok",
                            json!({
                                "client_id": device.id,
                                "enc_enabled": device.enc_enabled,
                            }),
                        );
                        info!(device_id = %device.id, "reauth successful");
                        return Ok(());
                    }
                    Err(err) => {
                        info!(
                            reason = %err.reason,
                            "reauth failed, falling back to register_new"
                        );
                        // Fall through to register_new.
                    }
                }
            }
        }

        // First-time register (or reauth fallback).
        let device = self
            .state
            .device_mgr
            .register_new(
                &p.device_pubkey,
                p.device_dh_pubkey.as_deref().unwrap_or(""),
                &p.hostname,
                &p.os,
                &self.remote_ip,
            )
            .map_err(|e| e.to_string())?;

        self.state.device_mgr.add_pending_conn(
            device.id.clone(),
            self.tx.clone(),
            self.remote_ip.clone(),
        );
        self.device = Some(device.clone());
        self.is_pending = true;
        self.is_authorized = false;

        self.send_text(
            "register_pending",
            json!({
                "client_id": device.id,
                "message": "waiting for admin approval",
            }),
        );
        info!(
            device_id = %device.id,
            hostname = %device.hostname,
            "device registered as pending"
        );
        Ok(())
    }

    async fn handle_tunnel_open(&mut self, payload: Option<serde_json::Value>) -> Result<(), String> {
        if !self.is_authorized {
            return Err("tunnel_open before authorization".to_string());
        }
        let device = self
            .device
            .as_ref()
            .ok_or_else(|| "no device for tunnel_open".to_string())?
            .clone();
        let payload = payload.unwrap_or(serde_json::Value::Null);
        let p: TunnelOpenPayload = serde_json::from_value(payload).map_err(|e| e.to_string())?;

        let exposure = TunnelExposure::parse(&p.protocol)
            .or_else(|_| TunnelExposure::parse("public"))
            .map_err(|e| e.to_string())?;

        match self
            .state
            .tunnel_mgr
            .create_tunnel(
                p.tunnel_id.clone(),
                device.id.clone(),
                self.tx.clone(),
                p.local_addr,
                p.local_port,
                exposure,
            )
            .await
        {
            Ok(port) => {
                let ack = TunnelOpenAckPayload {
                    tunnel_id: p.tunnel_id,
                    public_port: port,
                    success: true,
                    error: None,
                };
                let value = serde_json::to_value(&ack).map_err(|e| e.to_string())?;
                self.send_text("tunnel_open_ack", value);
                Ok(())
            }
            Err(e) => {
                let ack = TunnelOpenAckPayload {
                    tunnel_id: p.tunnel_id,
                    public_port: 0,
                    success: false,
                    error: Some(e.clone()),
                };
                let value = serde_json::to_value(&ack).map_err(|e| e.to_string())?;
                self.send_text("tunnel_open_ack", value);
                Ok(())
            }
        }
    }

    async fn handle_tunnel_close(&mut self, payload: Option<serde_json::Value>) -> Result<(), String> {
        if !self.is_authorized {
            return Err("tunnel_close before authorization".to_string());
        }
        let payload = payload.unwrap_or(serde_json::Value::Null);
        let p: TunnelClosePayload = serde_json::from_value(payload).map_err(|e| e.to_string())?;
        self.state
            .tunnel_mgr
            .close_tunnel(&p.tunnel_id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn register_authorized_sender(&self) {
        if let Some(d) = &self.device {
            self.state
                .authorized_senders
                .insert(d.id.clone(), self.tx.clone());
        }
    }

    fn maybe_promote_pending_to_authorized(&mut self) {
        let Some(d) = self.device.as_ref() else {
            return;
        };
        if self.is_authorized || !self.is_pending {
            return;
        }
        if let Some(latest) = self.state.state_store.get_device(&d.id) {
            if matches!(latest.status, DeviceStatus::Authorized) {
                self.is_pending = false;
                self.is_authorized = true;
                self.register_authorized_sender();
                info!(
                    device_id = %latest.id,
                    "device transitioned pending → authorized"
                );
            }
        }
    }

    fn cleanup(&self) {
        if let Some(d) = &self.device {
            if self.is_pending
                && DeviceManager::remove_self_pending(&self.state.device_mgr, &d.id, &self.tx)
            {
                debug!(device_id = %d.id, "removed own pending conn on disconnect");
            }
            if self.is_authorized {
                // Only remove if our sender still matches (avoids evicting a
                // newer reconnect).
                if let Some(entry) = self.state.authorized_senders.get(&d.id) {
                    if entry.same_channel(&self.tx) {
                        drop(entry);
                        self.state.authorized_senders.remove(&d.id);
                    }
                }
                // Also tear down any tunnels owned by this device.
                let to_close: Vec<String> = self
                    .state
                    .tunnel_mgr
                    .list_tunnels_by_client(&d.id)
                    .iter()
                    .map(|t| t.tunnel_id.clone())
                    .collect();
                let mgr = self.state.tunnel_mgr.clone();
                tokio::spawn(async move {
                    for tid in to_close {
                        if let Err(e) = mgr.close_tunnel(&tid).await {
                            warn!(tunnel_id = %tid, error = %e, "failed to close tunnel on disconnect");
                        }
                    }
                });
            }
        }
    }
}
