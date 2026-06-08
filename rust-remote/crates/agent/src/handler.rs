//! Server→agent message handling.
//!
//! The handler drives the WebSocket reader half (the writer half is owned
//! by `agent.rs`'s writer task). Text frames are routed to a small
//! state machine; binary frames carry `tunnel_data_bin` payloads and are
//! forwarded to the `AgentTunnelManager` for decryption + local dial.

use std::sync::Arc;

use futures::StreamExt;
use serde_json::Value;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};
use tunnel_rs_common::decode_envelope;

use crate::identity::AgentIdentity;
use crate::tunnel::{AgentTunnelManager, TunnelInfo};

type TunnelMgrSlot = Arc<tokio::sync::Mutex<Option<Arc<AgentTunnelManager>>>>;

#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// Server told us we are approved and pushed a (possibly empty) enc_key.
    Approved {
        client_id: String,
        enc_key_encrypted: Option<String>,
        server_dh_pubkey: Option<String>,
    },
    /// Server told us to re-register (probably reauth flow).
    ReauthRequested,
    /// Server told us the device was deleted. We must drop identity and
    /// start over as a fresh device.
    DeviceDeleted { reason: String },
    /// Server told us a new tunnel is now open; add it to the manager.
    TunnelOpened { info: TunnelInfo },
    /// Server told us a tunnel is closing; tear it down.
    TunnelClosed { tunnel_id: String },
    /// Server closed the connection.
    Closed,
}

pub struct Handler {
    pub identity: Arc<tokio::sync::Mutex<AgentIdentity>>,
    pub identity_dir: std::path::PathBuf,
    pub events: mpsc::UnboundedSender<ServerEvent>,
    pub disconnect: Arc<Notify>,
    /// Phase 6: tunnel manager is installed lazily once the device has
    /// been approved. The slot is `Some` from the start (so the handler
    /// itself is always wired up), but the inner `Option` is `None` until
    /// the `Approved` event flips it.
    pub tunnel_mgr: Option<TunnelMgrSlot>,
}

impl Handler {
    /// Drive the message loop on the given WebSocket reader half.
    pub async fn run_on<R>(&self, mut rx: R)
    where
        R: futures::Stream<
                Item = std::result::Result<
                    tokio_tungstenite::tungstenite::protocol::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            > + Unpin,
    {
        use tokio_tungstenite::tungstenite::protocol::Message;
        loop {
            match rx.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Err(e) = self.handle_text(&text).await {
                        warn!(error = %e, "text frame error");
                    }
                }
                Some(Ok(Message::Binary(bin))) => {
                    self.handle_binary(&bin).await;
                }
                Some(Ok(Message::Close(_))) | None => {
                    debug!("ws closed");
                    let _ = self.events.send(ServerEvent::Closed);
                    self.disconnect.notify_waiters();
                    return;
                }
                Some(Err(e)) => {
                    warn!(error = %e, "ws error");
                    let _ = self.events.send(ServerEvent::Closed);
                    self.disconnect.notify_waiters();
                    return;
                }
                _ => {}
            }
        }
    }

    async fn handle_binary(&self, bin: &[u8]) {
        let Some(slot) = self.tunnel_mgr.as_ref() else {
            debug!("no tunnel manager slot; dropping binary frame");
            return;
        };
        let mgr_opt = slot.lock().await.clone();
        let Some(mgr) = mgr_opt else {
            debug!("tunnel manager not yet armed; dropping binary frame");
            return;
        };
        let frame = match tunnel_rs_common::decode_frame(bin) {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, "bad binary frame");
                return;
            }
        };
        mgr.dispatch_from_server(&frame.tunnel_id, &frame.conn_id, &frame.data, frame.is_eof)
            .await;
    }

    async fn handle_text(&self, raw: &str) -> Result<(), String> {
        let env = decode_envelope(raw.as_bytes()).map_err(|e| e.to_string())?;
        match env.msg_type.as_str() {
            "register_ok" => {
                let payload: Value = env
                    .payload
                    .ok_or_else(|| "missing payload".to_string())?;
                let client_id = payload["client_id"]
                    .as_str()
                    .ok_or_else(|| "missing client_id".to_string())?
                    .to_string();
                eprintln!(
                    "[handler] register_ok client={} enc_hex_len={} dh_len={}",
                    client_id,
                    payload["enc_key_encrypted"].as_str().map(str::len).unwrap_or(0),
                    payload["server_dh_pubkey"].as_str().map(str::len).unwrap_or(0),
                );
                {
                    let mut id = self.identity.lock().await;
                    id.client_id = Some(client_id.clone());
                    if payload["enc_key_encrypted"].is_string()
                        && payload["server_dh_pubkey"].is_string()
                    {
                        let enc_hex = payload["enc_key_encrypted"].as_str().unwrap();
                        let srv_dh = payload["server_dh_pubkey"].as_str().unwrap();
                        eprintln!("[handler] enc_hex={enc_hex} srv_dh={srv_dh}");
                        if let Err(e) = id.install_enc_key(enc_hex, srv_dh) {
                            warn!(error = %e, "failed to decrypt enc_key");
                        } else {
                            eprintln!("[handler] enc_key installed OK");
                        }
                    }
                    let _ = id.save(&self.identity_dir).await;
                }
                let _ = self.events.send(ServerEvent::Approved {
                    client_id,
                    enc_key_encrypted: payload["enc_key_encrypted"].as_str().map(String::from),
                    server_dh_pubkey: payload["server_dh_pubkey"].as_str().map(String::from),
                });
                info!("registered and approved");
            }
            "register_pending" => {
                debug!("server says we are still pending; nothing to do");
            }
            "register_fail" => {
                let payload: Value = env.payload.unwrap_or(Value::Null);
                let reason = payload["reason"].as_str().unwrap_or("unknown").to_string();
                warn!(reason = %reason, "registration failed");
                let _ = self.events.send(ServerEvent::ReauthRequested);
            }
            "register_update" => {
                let payload: Value = env.payload.unwrap_or(Value::Null);
                if payload["enc_key_encrypted"].is_string()
                    && payload["server_dh_pubkey"].is_string()
                {
                    let enc_hex = payload["enc_key_encrypted"].as_str().unwrap();
                    let srv_dh = payload["server_dh_pubkey"].as_str().unwrap();
                    let mut id = self.identity.lock().await;
                    if let Err(e) = id.install_enc_key(enc_hex, srv_dh) {
                        warn!(error = %e, "failed to decrypt new enc_key");
                    }
                    let _ = id.save(&self.identity_dir).await;
                }
                info!("server rotated enc_key");
            }
            "device_deleted" => {
                let payload: Value = env.payload.unwrap_or(Value::Null);
                let reason = payload["reason"].as_str().unwrap_or("deleted").to_string();
                warn!(reason = %reason, "server says device was deleted");
                let _ = self.events.send(ServerEvent::DeviceDeleted { reason });
                self.disconnect.notify_waiters();
            }
            "tunnel_open_ack" => {
                let payload: Value = env.payload.unwrap_or(Value::Null);
                if let (Some(tid), Some(local_addr), Some(port)) = (
                    payload["tunnel_id"].as_str(),
                    payload["local_addr"].as_str(),
                    payload["local_port"].as_u64(),
                ) {
                    let _ = self.events.send(ServerEvent::TunnelOpened {
                        info: TunnelInfo {
                            tunnel_id: tid.to_string(),
                            local_addr: local_addr.to_string(),
                            local_port: port as u16,
                        },
                    });
                }
            }
            "tunnel_close" => {
                let payload: Value = env.payload.unwrap_or(Value::Null);
                if let Some(tid) = payload["tunnel_id"].as_str() {
                    let _ = self
                        .events
                        .send(ServerEvent::TunnelClosed { tunnel_id: tid.to_string() });
                }
            }
            "ping" => {
                // Pong scheduling is handled by `agent.rs`'s writer task.
                debug!("ping received; pong will be sent by the main loop");
            }
            other => {
                debug!(msg_type = %other, "ignoring message");
            }
        }
        Ok(())
    }
}
