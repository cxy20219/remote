//! Tunnel management: port allocation, listener accept loop, external
//! connection handling, and AES-GCM forwarding to the agent.
//!
//! The port allocation strategy mirrors Go's: `net.Listen` first, then
//! register the listener. This sidesteps the TOCTOU race that plagues
//! "check-then-bind" implementations. Ports already bound by another
//! process are recorded in `unavailable_ports` so the same port isn't tried
//! repeatedly during the same session.
//!
//! Listener sharing: each port's `TcpListener` lives behind
//! `Arc<tokio::sync::Mutex<_>>` so the accept loop can call `.accept()`
//! without holding the manager's `RwLock` across an await point.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};
use tracing::{debug, warn};
use tunnel_rs_common::{encode_frame, CryptoManager, TUNNEL_CHUNK_SIZE};

use crate::device_mgr::ServerOutMsg;
use crate::persist::StateStore;
use crate::security::{is_ip_whitelisted, BlacklistManager, RateLimiter};
use crate::state::ServerSettings;

pub const TUNNEL_EXPOSURE_PUBLIC: &str = "public";
pub const TUNNEL_EXPOSURE_SERVER_LOCAL: &str = "server_local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelExposure {
    Public,
    ServerLocal,
}

impl TunnelExposure {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "" | TUNNEL_EXPOSURE_PUBLIC => Ok(TunnelExposure::Public),
            TUNNEL_EXPOSURE_SERVER_LOCAL => Ok(TunnelExposure::ServerLocal),
            other => Err(format!("unsupported exposure: {other}")),
        }
    }

    pub fn bind_addr(self) -> IpAddr {
        match self {
            TunnelExposure::Public => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            TunnelExposure::ServerLocal => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TunnelExposure::Public => TUNNEL_EXPOSURE_PUBLIC,
            TunnelExposure::ServerLocal => TUNNEL_EXPOSURE_SERVER_LOCAL,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelStatus {
    Active,
    Closing,
}

#[derive(Debug, Clone)]
pub struct PortStatusSnapshot {
    pub range_start: u16,
    pub range_end: u16,
    pub total: u16,
    pub allocated: usize,
    pub unavailable: Vec<u16>,
}

pub struct Tunnel {
    pub tunnel_id: String,
    pub client_id: String,
    pub sender: mpsc::UnboundedSender<ServerOutMsg>,
    pub public_port: u16,
    pub exposure: TunnelExposure,
    pub bind_addr: IpAddr,
    pub local_addr: String,
    pub local_port: u16,
    pub status: TunnelStatus,
    pub created_at: DateTime<Utc>,
    pub shutdown: Arc<Notify>,
}

pub struct ExternalConn {
    pub conn_id: String,
    pub tunnel_id: String,
    pub remote: SocketAddr,
}

#[derive(Default)]
struct Inner {
    tunnels: HashMap<String, Arc<Tunnel>>,
    public_ports: HashMap<u16, String>,
    ext_conns: HashMap<String, ExternalConn>,
    listeners: HashMap<u16, Arc<AsyncMutex<TcpListener>>>,
    unavailable_ports: HashSet<u16>,
    port_range: (u16, u16),
}

#[derive(Debug)]
enum ExtConnMsg {
    Data(Vec<u8>),
    Close,
}

pub struct TunnelManager {
    crypto_mgr: Arc<CryptoManager>,
    /// Cached settings handle; consulted by the anti-scan check
    /// (`accept_loop` / `is_ip_whitelisted`) to read the global IP
    /// whitelist without going through `StateStore`.
    settings: Arc<RwLock<ServerSettings>>,
    inner: RwLock<Inner>,
    /// Per-ext-conn write side, used by `dispatch_from_agent`. The reader
    /// half lives inside the ext_conn task.
    ext_streams: DashMap<String, mpsc::Sender<ExtConnMsg>>,
    /// Anti-scanning limiter (per-IP, per-window). 0 = disabled. Wired in
    /// by `AppState::with_store` so the same value backs both the WS
    /// `connLimiter` (Go parity: `MaxConnPerMin`).
    port_limiter: Arc<RateLimiter>,
    /// Blacklist for repeat-offender IPs. Each anti-scan violation adds
    /// one to the counter; reaching the threshold promotes the IP to the
    /// global blacklist.
    blacklist: Arc<BlacklistManager>,
    /// Used to read the per-device `ip_whitelist` when an external conn
    /// arrives; the manager borrows it on each accept.
    state_store: Arc<StateStore>,
}

impl TunnelManager {
    pub fn new(crypto_mgr: Arc<CryptoManager>, settings: Arc<RwLock<ServerSettings>>) -> Self {
        let range = {
            let s = settings.read();
            (s.port_range_start, s.port_range_end)
        };
        Self {
            crypto_mgr,
            settings,
            inner: RwLock::new(Inner {
                port_range: range,
                ..Default::default()
            }),
            ext_streams: DashMap::new(),
            port_limiter: Arc::new(RateLimiter::new(0, Duration::from_secs(60))),
            blacklist: Arc::new(BlacklistManager::new(0)),
            state_store: Arc::new(StateStore::new_in_memory_handle()),
        }
    }

    /// Wire up the anti-scanning dependencies and the state store. The
    /// caller (usually `AppState::with_store`) passes the same limiter and
    /// blacklist that back the WS handler so a single setting controls
    /// both surfaces. Takes `&mut self` so the Arc fields can be
    /// assigned without interior mutability. The caller is expected to
    /// invoke this once during `AppState` construction (i.e. while the
    /// `Arc<TunnelManager>` still has a strong count of 1).
    pub fn bind_state(
        &mut self,
        port_limiter: Arc<RateLimiter>,
        blacklist: Arc<BlacklistManager>,
        state_store: Arc<StateStore>,
    ) {
        self.port_limiter = port_limiter;
        self.blacklist = blacklist;
        self.state_store = state_store;
    }

    pub fn set_port_range(&self, start: u16, end: u16) {
        let mut guard = self.inner.write();
        guard.port_range = (start, end);
    }

    pub fn port_status(&self) -> PortStatusSnapshot {
        let inner = self.inner.read();
        let total = inner.port_range.1 - inner.port_range.0 + 1;
        let mut unavailable: Vec<u16> = inner.unavailable_ports.iter().copied().collect();
        unavailable.sort_unstable();
        PortStatusSnapshot {
            range_start: inner.port_range.0,
            range_end: inner.port_range.1,
            total,
            allocated: inner.public_ports.len(),
            unavailable,
        }
    }

    // ---------- create / close ----------

    pub async fn create_tunnel(
        self: &Arc<Self>,
        tunnel_id: String,
        client_id: String,
        sender: mpsc::UnboundedSender<ServerOutMsg>,
        local_addr: String,
        local_port: u16,
        exposure: TunnelExposure,
    ) -> Result<u16, String> {
        if self.inner.read().tunnels.contains_key(&tunnel_id) {
            return Err(format!("tunnel already exists: {tunnel_id}"));
        }

        let bind = exposure.bind_addr();
        let (port, listener) = self.allocate_port(bind).await?;
        let listener = Arc::new(AsyncMutex::new(listener));
        let shutdown = Arc::new(Notify::new());

        let tunnel = Arc::new(Tunnel {
            tunnel_id: tunnel_id.clone(),
            client_id: client_id.clone(),
            sender: sender.clone(),
            public_port: port,
            exposure,
            bind_addr: bind,
            local_addr: local_addr.clone(),
            local_port,
            status: TunnelStatus::Active,
            created_at: Utc::now(),
            shutdown: shutdown.clone(),
        });

        let listener_for_loop = listener.clone();
        {
            let mut guard = self.inner.write();
            guard.listeners.insert(port, listener);
            guard.tunnels.insert(tunnel_id.clone(), tunnel.clone());
            guard.public_ports.insert(port, tunnel_id.clone());
        }

        let mgr = self.clone();
        let tunnel_id_for_loop = tunnel_id.clone();
        tokio::spawn(async move {
            mgr.accept_loop(tunnel_id_for_loop, listener_for_loop, shutdown)
                .await;
        });

        debug!(
            tunnel_id = %tunnel_id,
            client_id = %client_id,
            public_port = port,
            local_addr = %local_addr,
            local_port = local_port,
            exposure = %exposure.as_str(),
            "tunnel created"
        );
        Ok(port)
    }

    pub async fn close_tunnel(self: &Arc<Self>, tunnel_id: &str) -> Result<(), String> {
        let (port_opt, shutdown_opt, ext_to_close) = {
            let mut guard = self.inner.write();
            let Some(tunnel) = guard.tunnels.remove(tunnel_id) else {
                return Ok(());
            };
            guard.public_ports.remove(&tunnel.public_port);
            let listener = guard.listeners.remove(&tunnel.public_port);
            let to_close: Vec<String> = guard
                .ext_conns
                .iter()
                .filter(|(_, c)| c.tunnel_id == tunnel_id)
                .map(|(k, _)| k.clone())
                .collect();
            for k in &to_close {
                guard.ext_conns.remove(k);
                self.ext_streams.remove(k);
            }
            (
                Some((tunnel.public_port, listener)),
                Some(tunnel.shutdown.clone()),
                to_close,
            )
        };

        // Signal accept loop + drain leftover ext conns.
        if let Some((port, Some(l))) = port_opt {
            drop(l);
            debug!(port, "tunnel listener dropped");
        }
        if let Some(shutdown) = shutdown_opt {
            shutdown.notify_waiters();
        }
        for conn_id in ext_to_close {
            self.remove_ext_stream(&conn_id);
        }
        debug!(tunnel_id, "tunnel closed");
        Ok(())
    }

    pub fn get_tunnel(&self, tunnel_id: &str) -> Option<Arc<Tunnel>> {
        self.inner.read().tunnels.get(tunnel_id).cloned()
    }

    pub fn list_tunnels_by_client(&self, client_id: &str) -> Vec<Arc<Tunnel>> {
        self.inner
            .read()
            .tunnels
            .values()
            .filter(|t| t.client_id == client_id)
            .cloned()
            .collect()
    }

    pub fn list_tunnels(&self) -> Vec<Arc<Tunnel>> {
        self.inner.read().tunnels.values().cloned().collect()
    }

    pub fn get_tunnel_by_port(&self, port: u16) -> Option<Arc<Tunnel>> {
        let inner = self.inner.read();
        inner
            .public_ports
            .get(&port)
            .and_then(|tid| inner.tunnels.get(tid).cloned())
    }

    // ---------- agent → ext conn ----------

    pub async fn dispatch_from_agent(
        &self,
        tunnel_id: &str,
        conn_id: &str,
        plaintext: &[u8],
        is_eof: bool,
    ) {
        if is_eof {
            if let Some(tx) = self.ext_streams.get(conn_id).map(|s| s.clone()) {
                let _ = tx.send(ExtConnMsg::Close).await;
            }
            return;
        }
        let Some(tx) = self.ext_streams.get(conn_id).map(|s| s.clone()) else {
            debug!(tunnel_id, conn_id, "no live ext conn, dropping data");
            return;
        };
        if let Err(e) = tx.send(ExtConnMsg::Data(plaintext.to_vec())).await {
            warn!(tunnel_id, conn_id, error = %e, "ext conn channel closed");
        }
    }

    // ---------- port allocation ----------

    async fn allocate_port(self: &Arc<Self>, bind: IpAddr) -> Result<(u16, TcpListener), String> {
        let (start, end) = self.inner.read().port_range;
        for port in start..=end {
            // Quick check with a short read lock.
            {
                let guard = self.inner.read();
                if guard.public_ports.contains_key(&port)
                    || guard.unavailable_ports.contains(&port)
                {
                    continue;
                }
            }
            // Bind outside any lock — parking_lot guards are !Send and cannot
            // live across an `.await`.
            let addr = SocketAddr::new(bind, port);
            match TcpListener::bind(addr).await {
                Ok(l) => {
                    // Re-acquire write lock to claim the port. If someone
                    // else beat us, drop the listener and try next port.
                    let mut guard = self.inner.write();
                    if guard.public_ports.contains_key(&port) {
                        continue;
                    }
                    guard.public_ports.insert(port, String::new()); // tentative
                    drop(guard);
                    return Ok((port, l));
                }
                Err(e) => {
                    let mut guard = self.inner.write();
                    guard.unavailable_ports.insert(port);
                    debug!(port, bind = %bind, error = %e, "port occupied, marking unavailable");
                }
            }
        }
        Err(format!("no available ports in range {start}-{end}"))
    }

    // ---------- accept loop + ext conn ----------

    async fn accept_loop(
        self: Arc<Self>,
        tunnel_id: String,
        listener: Arc<AsyncMutex<TcpListener>>,
        shutdown: Arc<Notify>,
    ) {
        loop {
            let guard = listener.lock().await;
            tokio::select! {
                biased;
                _ = shutdown.notified() => {
                    debug!(tunnel_id, "accept loop exiting via shutdown");
                    return;
                }
                accept_result = guard.accept() => {
                    drop(guard);
                    match accept_result {
                        Ok((stream, addr)) => {
                            if let Some(reason) = self.check_external_acl(&tunnel_id, addr.ip()) {
                                warn!(
                                    tunnel_id = %tunnel_id,
                                    remote = %addr,
                                    reason = %reason,
                                    "external connection rejected"
                                );
                                drop(stream);
                                continue;
                            }
                            let conn_id = format!(
                                "{tunnel_id}-{}",
                                &uuid::Uuid::new_v4().to_string()[..8]
                            );
                            debug!(
                                tunnel_id,
                                conn_id,
                                remote = %addr,
                                "external connection accepted"
                            );
                            self.spawn_ext_conn(stream, tunnel_id.clone(), conn_id, addr);
                        }
                        Err(e) => {
                            // Listener likely closed by `close_tunnel`.
                            debug!(tunnel_id, error = %e, "accept error; loop ending");
                            return;
                        }
                    }
                }
            }
        }
    }

    fn spawn_ext_conn(
        self: &Arc<Self>,
        stream: TcpStream,
        tunnel_id: String,
        conn_id: String,
        remote: SocketAddr,
    ) {
        let (tx, mut rx) = mpsc::channel::<ExtConnMsg>(8);
        self.ext_streams.insert(conn_id.clone(), tx);
        self.inner.write().ext_conns.insert(
            conn_id.clone(),
            ExternalConn {
                conn_id: conn_id.clone(),
                tunnel_id: tunnel_id.clone(),
                remote,
            },
        );

        let mgr = self.clone();
        let conn_id_for_task = conn_id.clone();
        let tunnel_id_for_task = tunnel_id.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buf = vec![0u8; TUNNEL_CHUNK_SIZE];
            loop {
                tokio::select! {
                    biased;
                    msg = rx.recv() => {
                        match msg {
                            Some(ExtConnMsg::Data(data)) => {
                                if let Err(e) = stream.write_all(&data).await {
                                    warn!(conn_id = %conn_id_for_task, error = %e, "ext conn write error");
                                    break;
                                }
                            }
                            Some(ExtConnMsg::Close) | None => break,
                        }
                    }
                    read = stream.read(&mut buf) => {
                        match read {
                            Ok(0) => {
                                mgr.send_to_agent_eof(&tunnel_id_for_task, &conn_id_for_task).await;
                                break;
                            }
                            Ok(n) => {
                                let data = &buf[..n];
                                if let Err(e) =
                                    mgr.send_to_agent_data(&tunnel_id_for_task, &conn_id_for_task, data).await
                                {
                                    warn!(conn_id = %conn_id_for_task, error = %e, "failed to forward ext→agent");
                                    break;
                                }
                            }
                            Err(e) => {
                                debug!(conn_id = %conn_id_for_task, error = %e, "ext conn read error");
                                mgr.send_to_agent_eof(&tunnel_id_for_task, &conn_id_for_task).await;
                                break;
                            }
                        }
                    }
                }
            }
            mgr.inner.write().ext_conns.remove(&conn_id_for_task);
            mgr.remove_ext_stream(&conn_id_for_task);
            debug!(conn_id = %conn_id_for_task, "ext conn task ended");
        });
    }

    fn remove_ext_stream(&self, conn_id: &str) {
        self.ext_streams.remove(conn_id);
    }

    /// Anti-scanning gate for incoming external connections. Returns
    /// `Some(reason)` to reject; `None` to accept. Mirrors Go's
    /// `tunnel.go` accept loop: localhost bypass → blacklist reject →
    /// global whitelist bypass → per-device whitelist bypass → limiter
    /// check (with violation accounting).
    ///
    /// Public so integration tests can drive the policy without standing
    /// up a real TcpListener bound to a non-loopback interface.
    pub fn check_external_acl(&self, tunnel_id: &str, remote_ip: IpAddr) -> Option<&'static str> {
        // Localhost (loopback v4 + v6) always passes.
        if remote_ip.is_loopback() {
            return None;
        }
        if self.blacklist.is_blacklisted(remote_ip) {
            return Some("blacklisted");
        }
        let (global_white, device_white) = {
            let s = self.settings.read();
            (s.global_whitelist.clone(), self.device_whitelist(tunnel_id))
        };
        if is_ip_whitelisted(remote_ip, &global_white) {
            return None;
        }
        if is_ip_whitelisted(remote_ip, &device_white) {
            return None;
        }
        if self.port_limiter.allow(remote_ip) {
            return None;
        }
        self.blacklist.add_violation(remote_ip);
        Some("rate_limited")
    }

    fn device_whitelist(&self, tunnel_id: &str) -> Vec<String> {
        let client_id = {
            let inner = self.inner.read();
            inner
                .tunnels
                .get(tunnel_id)
                .map(|t| t.client_id.clone())
        };
        let Some(client_id) = client_id else {
            return Vec::new();
        };
        self.state_store
            .get_device(&client_id)
            .map(|d| d.ip_whitelist.clone())
            .unwrap_or_default()
    }

    async fn send_to_agent_data(
        &self,
        tunnel_id: &str,
        conn_id: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let (sender, client_id) = {
            let inner = self.inner.read();
            let tunnel = inner
                .tunnels
                .get(tunnel_id)
                .ok_or_else(|| format!("tunnel {tunnel_id} not found"))?;
            (tunnel.sender.clone(), tunnel.client_id.clone())
        };
        let ciphertext = self
            .crypto_mgr
            .encrypt(&client_id, data)
            .map_err(|e| e.to_string())?;
        let frame = encode_frame(tunnel_id, conn_id, &ciphertext, false)
            .map_err(|e| e.to_string())?;
        sender
            .send(ServerOutMsg::Binary(frame))
            .map_err(|e| format!("agent channel closed: {e}"))?;
        Ok(())
    }

    async fn send_to_agent_eof(&self, tunnel_id: &str, conn_id: &str) {
        if let Err(e) = self.send_to_agent_data_empty(tunnel_id, conn_id, true).await {
            debug!(tunnel_id, conn_id, error = %e, "could not push EOF to agent");
        }
    }

    async fn send_to_agent_data_empty(
        &self,
        tunnel_id: &str,
        conn_id: &str,
        is_eof: bool,
    ) -> Result<(), String> {
        let sender = {
            let inner = self.inner.read();
            let tunnel = inner
                .tunnels
                .get(tunnel_id)
                .ok_or_else(|| format!("tunnel {tunnel_id} not found"))?;
            tunnel.sender.clone()
        };
        let frame = encode_frame(tunnel_id, conn_id, &[], is_eof)
            .map_err(|e| e.to_string())?;
        sender
            .send(ServerOutMsg::Binary(frame))
            .map_err(|e| format!("agent channel closed: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Arc<RwLock<ServerSettings>> {
        // Use a high range to avoid colliding with anything else during tests.
        let s = ServerSettings {
            port_range_start: 30000,
            port_range_end: 30100,
            ..ServerSettings::default()
        };
        Arc::new(RwLock::new(s))
    }

    fn mgr() -> Arc<TunnelManager> {
        let crypto = Arc::new(CryptoManager::new());
        Arc::new(TunnelManager::new(crypto, settings()))
    }

    /// Build a manager whose anti-scan stack is fully wired so the
    /// `check_external_acl` policy can be exercised directly.
    fn mgr_with_acl(
        port_limit: u32,
        blacklist_threshold: u32,
        global_whitelist: Vec<String>,
    ) -> Arc<TunnelManager> {
        let crypto = Arc::new(CryptoManager::new());
        // Build a settings handle that the manager owns and that we can
        // also mutate later — `state_store` keeps its own copy for
        // device whitelist lookups.
        let shared_settings = settings();
        shared_settings.write().global_whitelist = global_whitelist;
        let state_store = Arc::new(crate::persist::StateStore::new_in_memory());
        let mut m = TunnelManager::new(crypto, shared_settings.clone());
        let port_limiter = Arc::new(RateLimiter::new(
            port_limit,
            std::time::Duration::from_secs(60),
        ));
        let blacklist = Arc::new(BlacklistManager::new(blacklist_threshold));
        m.bind_state(port_limiter, blacklist, state_store);
        Arc::new(m)
    }

    fn dummy_sender() -> (
        mpsc::UnboundedSender<ServerOutMsg>,
        mpsc::UnboundedReceiver<ServerOutMsg>,
    ) {
        mpsc::unbounded_channel()
    }

    #[tokio::test]
    async fn create_and_close() {
        let m = mgr();
        let (tx, _rx) = dummy_sender();
        let port = m
            .create_tunnel(
                "t-1".into(),
                "c-1".into(),
                tx,
                "127.0.0.1".into(),
                22,
                TunnelExposure::ServerLocal,
            )
            .await
            .unwrap();
        assert!((30000..=30100).contains(&port));
        assert!(m.get_tunnel("t-1").is_some());
        m.close_tunnel("t-1").await.unwrap();
        assert!(m.get_tunnel("t-1").is_none());
    }

    #[tokio::test]
    async fn rejects_duplicate_tunnel_id() {
        let m = mgr();
        let (tx, _rx) = dummy_sender();
        m.create_tunnel(
            "t".into(),
            "c".into(),
            tx.clone(),
            "127.0.0.1".into(),
            22,
            TunnelExposure::ServerLocal,
        )
        .await
        .unwrap();
        let err = m
            .create_tunnel(
                "t".into(),
                "c".into(),
                tx,
                "127.0.0.1".into(),
                22,
                TunnelExposure::ServerLocal,
            )
            .await
            .unwrap_err();
        assert!(err.contains("already exists"), "got {err}");
    }

    #[tokio::test]
    async fn port_status_reflects_allocations() {
        let m = mgr();
        let (tx, _rx) = dummy_sender();
        m.create_tunnel(
            "t".into(),
            "c".into(),
            tx,
            "127.0.0.1".into(),
            22,
            TunnelExposure::ServerLocal,
        )
        .await
        .unwrap();
        let s = m.port_status();
        assert_eq!(s.allocated, 1);
        assert_eq!(s.range_start, 30000);
        assert_eq!(s.range_end, 30100);
    }

    #[tokio::test]
    async fn accepts_through_listener() {
        let m = mgr();
        // Pretend "c" was approved and has a per-device AES key installed.
        m.crypto_mgr.set_key("c", &[0u8; 32]).unwrap();
        let (tx, mut rx) = dummy_sender();
        let port = m
            .create_tunnel(
                "t".into(),
                "c".into(),
                tx,
                "127.0.0.1".into(),
                0, // not used; just to populate
                TunnelExposure::ServerLocal,
            )
            .await
            .unwrap();

        // Spawn a client that connects and writes "hello\n".
        let client_task = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            use tokio::io::AsyncWriteExt;
            s.write_all(b"hello\n").await.unwrap();
            // hold the connection open briefly so the server reads it
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        // Drain the first agent-side message: it should be the encrypted
        // "hello\n" payload.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for ext→agent message")
            .expect("channel closed");
        let frame = match msg {
            ServerOutMsg::Binary(b) => b,
            other => panic!("expected binary frame, got {other:?}"),
        };
        let decoded = tunnel_rs_common::decode_frame(&frame).unwrap();
        assert!(!decoded.is_eof);
        assert!(decoded.data.len() > 12, "ciphertext must include GCM nonce+tag");

        // The ciphertext round-trips back to plaintext using the same key.
        let plain = m.crypto_mgr.decrypt("c", &decoded.data).unwrap();
        assert_eq!(plain, b"hello\n");

        // Cleanup
        client_task.await.unwrap();
        m.close_tunnel("t").await.unwrap();
    }

    // ---------- large frame forwarding ----------

    #[tokio::test]
    async fn large_frame_forwards_in_chunks() {
        let m = mgr();
        m.crypto_mgr.set_key("c", &[0xCD; 32]).unwrap();
        let (tx, mut rx) = dummy_sender();
        let port = m
            .create_tunnel(
                "t".into(),
                "c".into(),
                tx,
                "127.0.0.1".into(),
                0,
                TunnelExposure::ServerLocal,
            )
            .await
            .unwrap();

        // 1.5x the chunk size — the server must hand two separate frames
        // to the agent (or one larger one), but no byte must be lost.
        let payload_len = (TUNNEL_CHUNK_SIZE as f64 * 1.5) as usize;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let client_task = tokio::spawn({
            let payload = payload.clone();
            async move {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                use tokio::io::AsyncWriteExt;
                s.write_all(&payload).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        // Drain frames until we have the full payload reassembled.
        let mut collected: Vec<u8> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while collected.len() < payload_len && std::time::Instant::now() < deadline {
            let remaining = std::time::Duration::from_millis(200);
            let msg = match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(m)) => m,
                _ => break,
            };
            let frame = match msg {
                ServerOutMsg::Binary(b) => b,
                other => panic!("expected binary frame, got {other:?}"),
            };
            let decoded = tunnel_rs_common::decode_frame(&frame).unwrap();
            let plain = m.crypto_mgr.decrypt("c", &decoded.data).unwrap();
            collected.extend_from_slice(&plain);
        }
        assert_eq!(
            collected.len(),
            payload_len,
            "expected {payload_len} bytes, got {}",
            collected.len()
        );
        assert_eq!(collected, payload, "payload mismatch across chunk boundary");

        client_task.await.unwrap();
        m.close_tunnel("t").await.unwrap();
    }

    // ---------- agent → ext conn ----------

    #[tokio::test]
    async fn dispatch_from_agent_writes_to_ext_conn() {
        let m = mgr();
        m.crypto_mgr.set_key("c", &[0xEF; 32]).unwrap();
        let (tx, mut rx) = dummy_sender();
        let port = m
            .create_tunnel(
                "t".into(),
                "c".into(),
                tx,
                "127.0.0.1".into(),
                0,
                TunnelExposure::ServerLocal,
            )
            .await
            .unwrap();

        // The ext conn task uses a tokio::select! that polls the agent
        // mpsc and the client stream. With `biased` the mpsc wins when
        // both are ready, but if the client hasn't sent any data the
        // stream branch is suspended. To avoid a deadlock where the
        // client waits for the agent's bytes and the ext conn task waits
        // for the client's bytes, have the client send a single byte
        // first to kick the loop.
        let client_task = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            s.write_all(b"k").await.unwrap();
            let mut buf = vec![0u8; 32];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                s.read(&mut buf),
            )
            .await
            .expect("read timeout")
            .expect("read err");
            (buf, n)
        });

        // Give the accept loop a moment to register the ext conn and
        // for the ext conn task to consume the leading "k" byte.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Discover the freshly-created conn_id.
        let conn_id = {
            let inner = m.inner.read();
            inner
                .ext_conns
                .keys()
                .next()
                .cloned()
                .expect("expected an ext conn registered")
        };

        // Drain the leading ext→agent frame carrying "k".
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        m.dispatch_from_agent("t", &conn_id, b"ping-from-agent", false)
            .await;

        let (buf, n) = client_task.await.unwrap();
        // The dispatcher wrote 15 bytes ("ping-from-agent"). On rare
        // occasion the underlying TCP read can return the 15 + a stray
        // zero-length fragment of the EOF frame; assert on the leading
        // 15 bytes explicitly.
        assert!(
            n >= 15 && &buf[..15] == b"ping-from-agent",
            "expected leading 15 bytes to be 'ping-from-agent', got n={n} buf={:02x?}",
            &buf[..n.min(32)]
        );

        m.close_tunnel("t").await.unwrap();
    }

    // ---------- EOF path ----------

    #[tokio::test]
    async fn ext_conn_close_pushes_eof_to_agent() {
        let m = mgr();
        m.crypto_mgr.set_key("c", &[0x77; 32]).unwrap();
        let (tx, mut rx) = dummy_sender();
        let port = m
            .create_tunnel(
                "t".into(),
                "c".into(),
                tx,
                "127.0.0.1".into(),
                0,
                TunnelExposure::ServerLocal,
            )
            .await
            .unwrap();

        // Connect, send some bytes, then drop → server should see read 0
        // and push an EOF frame.
        let conn_task = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            use tokio::io::AsyncWriteExt;
            s.write_all(b"hi").await.unwrap();
            // Drop closes the socket.
        });
        // Wait for the data frame + EOF frame. The data frame carries
        // the 2 bytes; the EOF frame is a zero-length body.
        let mut data_seen = false;
        let mut eof_seen = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline && !(data_seen && eof_seen) {
            let msg = match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                rx.recv(),
            )
            .await
            {
                Ok(Some(m)) => m,
                _ => break,
            };
            let frame = match msg {
                ServerOutMsg::Binary(b) => b,
                _ => continue,
            };
            let decoded = tunnel_rs_common::decode_frame(&frame).unwrap();
            if decoded.is_eof {
                eof_seen = true;
            } else {
                data_seen = true;
            }
        }
        assert!(data_seen, "expected a data frame before EOF");
        assert!(eof_seen, "expected an EOF frame after ext conn close");
        conn_task.await.unwrap();
        m.close_tunnel("t").await.unwrap();
    }

    // ---------- anti-scan policy ----------

    #[test]
    fn anti_scan_loopback_always_passes() {
        let m = mgr_with_acl(0, 0, vec![]);
        assert!(m.check_external_acl("t", "127.0.0.1".parse().unwrap()).is_none());
        assert!(m.check_external_acl("t", "::1".parse().unwrap()).is_none());
    }

    #[test]
    fn anti_scan_blocks_after_limit_and_accumulates_violations() {
        // port_limit=2, blacklist_threshold=3 (3rd violation promotes to blacklist)
        let m = mgr_with_acl(2, 3, vec![]);
        let ip: IpAddr = "10.0.0.42".parse().unwrap();
        assert!(m.check_external_acl("t", ip).is_none());
        assert!(m.check_external_acl("t", ip).is_none());
        // Third attempt should be rejected.
        let reason = m.check_external_acl("t", ip).unwrap();
        assert_eq!(reason, "rate_limited");
        // Two more violations push the counter to 3 → global blacklist.
        assert_eq!(m.check_external_acl("t", ip).unwrap(), "rate_limited");
        assert_eq!(m.check_external_acl("t", ip).unwrap(), "rate_limited");
        // From now on, blacklist check rejects before reaching the limiter.
        assert_eq!(m.check_external_acl("t", ip).unwrap(), "blacklisted");
    }

    #[test]
    fn anti_scan_global_whitelist_bypasses_limiter() {
        let m = mgr_with_acl(1, 0, vec!["10.0.0.0/24".into()]);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        // Limit is 1 but the IP is in the global whitelist, so it must
        // pass through unlimited times.
        for _ in 0..10 {
            assert!(
                m.check_external_acl("t", ip).is_none(),
                "whitelisted IP must bypass limiter"
            );
        }
    }

    #[test]
    fn anti_scan_limiter_zero_disables_check() {
        // port_limit=0 means "disabled" (matches RateLimiter::allow semantics)
        let m = mgr_with_acl(0, 0, vec![]);
        let ip: IpAddr = "10.0.0.99".parse().unwrap();
        for _ in 0..50 {
            assert!(m.check_external_acl("t", ip).is_none());
        }
    }
}
