//! Agent main loop.
//!
//! The agent's life cycle:
//!
//! 1. **Connect + register** — open a WebSocket, send `register` (either
//!    fresh or reauth), wait for `register_pending` / `register_ok` /
//!    `register_fail`.
//! 2. **Pending loop** — while the server has us as `pending`, we send
//!    periodic `ping`s so the connection doesn't die and the server can
//!    notice when it should push us into the working state.
//! 3. **Work loop** — once approved, the handler task takes over message
//!    processing and the tunnel manager starts relaying data.
//! 4. **Reconnect** — any disconnect resets the backoff and jumps back
//!    to step 1.
//!
//! The handler is created **after** registration. Until it spins up, the
//!    server's response to `register_*` is consumed by `connector::*`.
//! Once the handler is running, it processes the rest of the
//!    conversation (including the `register_ok` push that follows an
//!    admin approval).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::sleep;
use tracing::{error, info, warn};
use tunnel_rs_common::{message::WsMessage, CryptoManager};

use crate::config::Config;
use crate::connector::{self, Connector, RegisterResponse, WsStream};
use crate::handler::{Handler, ServerEvent};
use crate::identity::AgentIdentity;
use crate::reconnect::Reconnect;
use crate::tunnel::AgentTunnelManager;

pub struct Agent {
    config: Config,
    identity: Arc<Mutex<AgentIdentity>>,
    identity_dir: PathBuf,
    #[allow(dead_code)] // Phase 6 already-installed; used to install key on session start
    crypto_mgr: Arc<CryptoManager>,
}

impl Agent {
    pub fn new(
        config: Config,
        identity: Arc<Mutex<AgentIdentity>>,
        identity_dir: PathBuf,
        crypto_mgr: Arc<CryptoManager>,
    ) -> Self {
        Self {
            config,
            identity,
            identity_dir,
            crypto_mgr,
        }
    }

    pub async fn run(self) {
        let mut reconnect = Reconnect::new(
            Duration::from_secs(self.config.reconnect_interval),
            0,
            Duration::from_secs(self.config.reconnect_max),
        );

        loop {
            if !reconnect.should_retry() {
                error!("reconnect attempts exhausted; giving up");
                return;
            }

            match self.single_session().await {
                Ok(()) => {
                    info!("session ended cleanly; reconnecting");
                    reconnect.reset();
                }
                Err(e) => {
                    warn!(error = %e, "session ended with error; reconnecting");
                    reconnect.bump();
                }
            }

            info!(
                attempt = reconnect.attempts(),
                next_in = ?reconnect.current(),
                "reconnecting"
            );
            reconnect.wait().await;
        }
    }

    async fn single_session(&self) -> anyhow::Result<()> {
        // 1. connect + register
        let connector = Connector::new(self.config.server_addr(), self.config.tls)
            .with_tls_ca(self.config.tls_ca.clone())
            .with_insecure_skip_verify(self.config.insecure_skip_verify);
        let identity = self.identity.lock().await.clone();
        let hostname = hostname();
        let os_name = os();

        let (ws, resp) = if identity.client_id.is_some() {
            connector::register_reauth(&identity, &connector, &hostname, &os_name).await?
        } else {
            connector::register_new(&identity, &connector, &hostname, &os_name).await?
        };

        let client_id = match &resp {
            RegisterResponse::Pending { client_id } => {
                info!("registered as pending; awaiting admin approval");
                let mut id = self.identity.lock().await;
                id.client_id = Some(client_id.clone());
                let _ = id.save(&self.identity_dir).await;
                client_id.clone()
            }
            RegisterResponse::Ok {
                client_id,
                enc_key_encrypted,
                server_dh_pubkey,
                ..
            } => {
                info!("registered and approved on first connect");
                let mut id = self.identity.lock().await;
                id.client_id = Some(client_id.clone());
                if let (Some(enc), Some(dh)) = (enc_key_encrypted, server_dh_pubkey) {
                    if let Err(e) = id.install_enc_key(enc, dh) {
                        warn!(error = %e, "failed to decrypt enc_key");
                    }
                }
                let _ = id.save(&self.identity_dir).await;
                client_id.clone()
            }
            RegisterResponse::Failed { reason } => {
                anyhow::bail!("registration failed: {reason}");
            }
        };

        // 2. shared channels
        let (control_tx, mut control_rx) = mpsc::unbounded_channel::<WorkCmd>();
        let (binary_tx, mut binary_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (mut ws_tx, ws_rx) = ws.split();

        // 3. writer task
        let writer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    cmd = control_rx.recv() => {
                        let Some(cmd) = cmd else { break };
                        let res = match cmd {
                            WorkCmd::Ping => send_ping_writer(&mut ws_tx).await,
                        };
                        if res.is_err() { break; }
                    }
                    bin = binary_rx.recv() => {
                        let Some(bin) = bin else { break };
                        use tokio_tungstenite::tungstenite::protocol::Message;
                        if ws_tx.send(Message::Binary(bin)).await.is_err() { break; }
                    }
                }
            }
        });

        // 4. heartbeat
        let heartbeat = {
            let tx = control_tx.clone();
            let interval = Duration::from_secs(self.config.heartbeat_interval);
            tokio::spawn(async move {
                let mut first = true;
                loop {
                    if !first {
                        sleep(interval).await;
                    }
                    first = false;
                    tracing::info!(interval = ?interval, "sending heartbeat ping");
                    if tx.send(WorkCmd::Ping).is_err() {
                        break;
                    }
                }
            })
        };

        // 5. handler + tunnel manager
        let (events_tx, mut events_rx) = mpsc::unbounded_channel::<ServerEvent>();
        let disconnect = Arc::new(Notify::new());
        // The tunnel manager is `None` until the server pushes an
        // `Approved` event (i.e. an admin clicks approve). Once
        // installed, the handler starts dispatching binary frames.
        let tunnel_mgr_slot: Arc<tokio::sync::Mutex<Option<Arc<AgentTunnelManager>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let handler = Handler {
            identity: self.identity.clone(),
            identity_dir: self.identity_dir.clone(),
            events: events_tx.clone(),
            disconnect: disconnect.clone(),
            tunnel_mgr: Some(tunnel_mgr_slot.clone()),
        };
        let handler_task = tokio::spawn(async move {
            handler.run_on(ws_rx).await;
        });

        // 6. event loop
        loop {
            tokio::select! {
                _ = disconnect.notified() => {
                    tracing::debug!("disconnect notified");
                }
                ev = events_rx.recv() => {
                    let Some(ev) = ev else { break; };
                    match ev {
                        ServerEvent::DeviceDeleted { reason } => {
                            warn!(reason = %reason, "device deleted; clearing local identity");
                            let mut id = self.identity.lock().await;
                            id.client_id = None;
                            id.enc_key = None;
                            id.enc_enabled = false;
                            let _ = id.save(&self.identity_dir).await;
                            break;
                        }
                        ServerEvent::Closed => {
                            warn!("server closed the connection");
                            break;
                        }
                        ServerEvent::Approved { .. } => {
                            // Build the per-device AES context now that we
                            // have the key, then arm the tunnel manager.
                            let crypto = self.build_crypto_for_current_device(&client_id).await;
                            match crypto {
                                Ok(crypto) => {
                                    let mgr = Arc::new(AgentTunnelManager::new(
                                        crypto,
                                        client_id.clone(),
                                        binary_tx.clone(),
                                    ));
                                    *tunnel_mgr_slot.lock().await = Some(mgr);
                                    drop(binary_tx.clone());
                                    info!("tunnel manager armed; entering work state");
                                }
                                Err(e) => warn!(error = %e, "cannot arm tunnel manager"),
                            }
                        }
                        ServerEvent::ReauthRequested => break,
                        ServerEvent::TunnelOpened { info } => {
                            if let Some(mgr) = tunnel_mgr_slot.lock().await.as_ref() {
                                mgr.add_tunnel(info);
                            }
                        }
                        ServerEvent::TunnelClosed { tunnel_id } => {
                            if let Some(mgr) = tunnel_mgr_slot.lock().await.as_ref() {
                                mgr.remove_tunnel(&tunnel_id).await;
                            }
                        }
                    }
                }
            }
        }

        // cleanup
        heartbeat.abort();
        let _ = heartbeat.await;
        let _ = control_tx.send(WorkCmd::Ping);
        drop(control_tx);
        let _ = writer.await;
        handler_task.abort();
        let _ = handler_task.await;
        Ok(())
    }

    /// Build a `CryptoManager` with the current device's per-device AES
    /// key installed.
    async fn build_crypto_for_current_device(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Arc<CryptoManager>> {
        let id = self.identity.lock().await;
        let key = id.enc_key_bytes()?;
        let mgr = Arc::new(CryptoManager::new());
        mgr.set_key(client_id, &key)?;
        Ok(mgr)
    }
}

enum WorkCmd {
    Ping,
}

async fn send_ping_writer(
    ws: &mut futures::stream::SplitSink<
        WsStream,
        tokio_tungstenite::tungstenite::protocol::Message,
    >,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    let text = serde_json::to_string(&WsMessage::new("ping"))
        .map_err(|_| tokio_tungstenite::tungstenite::Error::AlreadyClosed)?;
    ws.send(tokio_tungstenite::tungstenite::protocol::Message::Text(text))
        .await
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .unwrap_or_else(|| "unknown".into())
        .trim()
        .to_string()
}

fn os() -> String {
    if cfg!(target_os = "linux") {
        "linux".into()
    } else if cfg!(target_os = "windows") {
        "windows".into()
    } else if cfg!(target_os = "macos") {
        "darwin".into()
    } else {
        "unknown".into()
    }
}
