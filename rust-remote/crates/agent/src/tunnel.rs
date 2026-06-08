//! Agent-side tunnel manager: receives `tunnel_data_bin` frames from the
//! server, decrypts them, dials the local service on demand, and writes
//! the plaintext to the local socket. Local-to-server traffic flows the
//! opposite way: a per-conn read task encrypts what it reads and pushes
//! the binary frame through the websocket writer.
//!
//! The manager owns:
//! - a `tunnels` map (`tunnel_id -> TunnelInfo`) so we can look up the
//!   local target whenever a new `conn_id` shows up.
//! - a `local_sends` map (`conn_id -> mpsc::Sender<LocalMsg>`) that drives
//!   the local socket. The first frame for a brand-new `conn_id`
//!   triggers a dial; subsequent frames reuse the existing writer.
//! - a single `ws_tx` channel that hands raw binary frames off to the
//!   websocket writer task — this lets the data path never block on the
//!   network.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use tunnel_rs_common::{encode_frame, CryptoManager};

pub const LOCAL_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub tunnel_id: String,
    pub local_addr: String,
    pub local_port: u16,
}

#[derive(Debug)]
pub enum LocalMsg {
    Data(Vec<u8>),
    Close,
}

pub struct AgentTunnelManager {
    crypto: Arc<CryptoManager>,
    client_id: String,
    /// Sink for outbound binary frames. The websocket writer task drains
    /// this and pushes them onto the wire.
    ws_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// `tunnel_id -> TunnelInfo`
    tunnels: RwLock<HashMap<String, TunnelInfo>>,
    /// `conn_id -> writer to the local socket`
    sends: DashMap<String, mpsc::Sender<LocalMsg>>,
}

impl AgentTunnelManager {
    pub fn new(
        crypto: Arc<CryptoManager>,
        client_id: String,
        ws_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            crypto,
            client_id,
            ws_tx,
            tunnels: RwLock::new(HashMap::new()),
            sends: DashMap::new(),
        }
    }

    /// Register a tunnel that the server just told us about (via
    /// `tunnel_open_ack`). Phase 5 already calls this from the agent
    /// when the user/admin opens a tunnel through the HTTP API; Phase 6
    /// also accepts a `tunnel_open` text frame for an in-band path.
    pub fn add_tunnel(&self, info: TunnelInfo) {
        self.tunnels.write().insert(info.tunnel_id.clone(), info);
    }

    pub async fn remove_tunnel(&self, tunnel_id: &str) {
        self.tunnels.write().remove(tunnel_id);
        // We don't track per-conn tunnel_id; conservatively drop every
        // conn that this manager owns. Phase 6 keeps the manager scoped
        // to a single agent process so this is safe.
        let to_close: Vec<String> =
            self.sends.iter().map(|e| e.key().clone()).collect();
        for conn_id in to_close {
            if let Some((_, tx)) = self.sends.remove(&conn_id) {
                let _ = tx.send(LocalMsg::Close).await;
            }
        }
    }

    /// Dispatch a `tunnel_data_bin` payload to the matching local conn.
    /// `ciphertext` is the raw frame data (nonce || AES-GCM ciphertext).
    /// The manager decrypts it using the per-device AES key installed at
    /// construction, then dials the local service on demand.
    pub async fn dispatch_from_server(
        &self,
        tunnel_id: &str,
        conn_id: &str,
        ciphertext: &[u8],
        is_eof: bool,
    ) {
        let info = {
            let guard = self.tunnels.read();
            guard.get(tunnel_id).cloned()
        };
        let Some(info) = info else {
            warn!(
                tunnel_id,
                "received data for unknown tunnel; dropping"
            );
            return;
        };

        if is_eof {
            if let Some((_, tx)) = self.sends.remove(conn_id) {
                let _ = tx.send(LocalMsg::Close).await;
            }
            return;
        }

        let plaintext = match self.crypto.decrypt(&self.client_id, ciphertext) {
            Ok(p) => p,
            Err(e) => {
                warn!(tunnel_id, conn_id, error = %e, "decrypt failed; closing ext conn");
                self.send_to_server_eof(tunnel_id, conn_id).await;
                return;
            }
        };

        // Get or create the writer for this conn_id.
        let tx = match self.sends.get(conn_id).map(|s| s.clone()) {
            Some(tx) => tx,
            None => {
                if let Err(e) = self.ensure_local_conn(&info, conn_id).await {
                    warn!(
                        tunnel_id,
                        conn_id,
                        error = %e,
                        "failed to dial local service; closing ext conn"
                    );
                    self.send_to_server_eof(tunnel_id, conn_id).await;
                    return;
                }
                self.sends
                    .get(conn_id)
                    .map(|s| s.clone())
                    .expect("ensure_local_conn registered the writer")
            }
        };

        if let Err(e) = tx.send(LocalMsg::Data(plaintext)).await {
            warn!(tunnel_id, conn_id, error = %e, "local conn channel closed");
        }
    }

    async fn ensure_local_conn(&self, info: &TunnelInfo, conn_id: &str) -> anyhow::Result<()> {
        let addr = (info.local_addr.as_str(), info.local_port);
        let stream = tokio::time::timeout(LOCAL_DIAL_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("dial timeout"))??;
        debug!(
            tunnel_id = %info.tunnel_id,
            conn_id,
            "connected to local service"
        );
        let (tx, mut rx) = mpsc::channel::<LocalMsg>(8);
        self.sends.insert(conn_id.to_string(), tx);

        let crypto = self.crypto.clone();
        let client_id = self.client_id.clone();
        let tunnel_id = info.tunnel_id.clone();
        let conn_id_owned = conn_id.to_string();
        let ws_tx = self.ws_tx.clone();
        let sends = self.sends.clone();

        tokio::spawn(async move {
            let mut stream = stream;
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                tokio::select! {
                    biased;
                    msg = rx.recv() => {
                        match msg {
                            Some(LocalMsg::Data(data)) => {
                                if let Err(e) = stream.write_all(&data).await {
                                    warn!(conn_id = %conn_id_owned, error = %e, "local write error");
                                    break;
                                }
                            }
                            Some(LocalMsg::Close) | None => break,
                        }
                    }
                    read = stream.read(&mut buf) => {
                        match read {
                            Ok(0) => {
                                push_to_server(&ws_tx, &crypto, &client_id, &tunnel_id, &conn_id_owned, &[], true).await;
                                break;
                            }
                            Ok(n) => {
                                let data = &buf[..n];
                                push_to_server(&ws_tx, &crypto, &client_id, &tunnel_id, &conn_id_owned, data, false).await;
                            }
                            Err(e) => {
                                warn!(conn_id = %conn_id_owned, error = %e, "local read error");
                                push_to_server(&ws_tx, &crypto, &client_id, &tunnel_id, &conn_id_owned, &[], true).await;
                                break;
                            }
                        }
                    }
                }
            }
            sends.remove(&conn_id_owned);
            debug!(conn_id = %conn_id_owned, "local conn task ended");
        });
        Ok(())
    }

    async fn send_to_server_eof(&self, tunnel_id: &str, conn_id: &str) {
        let frame = match encode_frame(tunnel_id, conn_id, &[], true) {
            Ok(f) => f,
            Err(e) => {
                warn!(tunnel_id, conn_id, error = %e, "could not encode EOF");
                return;
            }
        };
        let _ = self.ws_tx.send(frame);
    }
}

/// Small helper so the local-conn task can emit a binary frame without
/// holding a `&AgentTunnelManager` (which would require `'static`).
async fn push_to_server(
    ws_tx: &mpsc::UnboundedSender<Vec<u8>>,
    crypto: &CryptoManager,
    client_id: &str,
    tunnel_id: &str,
    conn_id: &str,
    data: &[u8],
    is_eof: bool,
) {
    let ciphertext = match crypto.encrypt(client_id, data) {
        Ok(c) => c,
        Err(e) => {
            warn!(client_id, error = %e, "encrypt failed");
            return;
        }
    };
    let frame = match encode_frame(tunnel_id, conn_id, &ciphertext, is_eof) {
        Ok(f) => f,
        Err(e) => {
            warn!(tunnel_id, conn_id, error = %e, "frame encode failed");
            return;
        }
    };
    let _ = ws_tx.send(frame);
}

// (no extra helpers needed beyond `mpsc::Sender::send().await`)

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn round_trip_through_local_service() {
        // Stand up a tiny "local service" that echoes whatever it reads.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let crypto = Arc::new(CryptoManager::new());
        crypto.set_key("c", &[0xAB; 32]).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mgr = AgentTunnelManager::new(crypto, "c".into(), tx);
        mgr.add_tunnel(TunnelInfo {
            tunnel_id: "t".into(),
            local_addr: "127.0.0.1".into(),
            local_port,
        });

        // Encrypt the payload the way the server would.
        let ciphertext = mgr.crypto.encrypt("c", b"hello").unwrap();

        mgr.dispatch_from_server("t", "conn-1", &ciphertext, false)
            .await;

        // The local service echoed; the task pushes the echo back through
        // ws_tx. Read it from rx and decode.
        let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("frame timeout")
            .expect("channel closed");
        let decoded = tunnel_rs_common::decode_frame(&frame).unwrap();
        let echoed = mgr.crypto.decrypt("c", &decoded.data).unwrap();
        assert_eq!(echoed, b"hello");
    }
}
