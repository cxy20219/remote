use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tunnel_rs_common::CryptoManager;

use crate::device_mgr::{DeviceManager, ServerOutMsg};
use crate::persist::StateStore;
use crate::security::{BlacklistManager, RateLimiter};
use crate::session::SessionManager;
use crate::tunnel::TunnelManager;

pub mod defaults {
    pub const PORT_RANGE_START: u16 = 10000;
    pub const PORT_RANGE_END: u16 = 20000;
    pub const MAX_TUNNELS_PER_CLIENT: u32 = 10;
    pub const DEFAULT_LOCAL_ADDR: &str = "127.0.0.1";
    pub const MAX_CONN_PER_MIN: u32 = 10;
    pub const LOGIN_RATE_LIMIT: u32 = 5;
    pub const BLACKLIST_THRESHOLD: u32 = 100;
    pub const MAX_BODY_SIZE_MB: u32 = 10;
    pub const HEARTBEAT_INTERVAL: u32 = 30;
    pub const HEARTBEAT_TIMEOUT: u32 = 90;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    #[serde(default = "default_port_range_start")]
    pub port_range_start: u16,
    #[serde(default = "default_port_range_end")]
    pub port_range_end: u16,
    #[serde(default = "default_max_tunnels_per_client")]
    pub max_tunnels_per_client: u32,
    #[serde(default = "default_default_local_addr")]
    pub default_local_addr: String,
    #[serde(default)]
    pub public_host: String,
    #[serde(default = "default_max_conn_per_min")]
    pub max_conn_per_min: u32,
    #[serde(default = "default_login_rate_limit")]
    pub login_rate_limit: u32,
    #[serde(default = "default_blacklist_threshold")]
    pub blacklist_threshold: u32,
    #[serde(default)]
    pub global_whitelist: Vec<String>,
    #[serde(default = "default_max_body_size_mb")]
    pub max_body_size_mb: u32,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u32,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u32,
}

fn default_port_range_start() -> u16 {
    defaults::PORT_RANGE_START
}
fn default_port_range_end() -> u16 {
    defaults::PORT_RANGE_END
}
fn default_max_tunnels_per_client() -> u32 {
    defaults::MAX_TUNNELS_PER_CLIENT
}
fn default_default_local_addr() -> String {
    defaults::DEFAULT_LOCAL_ADDR.to_string()
}
fn default_max_conn_per_min() -> u32 {
    defaults::MAX_CONN_PER_MIN
}
fn default_login_rate_limit() -> u32 {
    defaults::LOGIN_RATE_LIMIT
}
fn default_blacklist_threshold() -> u32 {
    defaults::BLACKLIST_THRESHOLD
}
fn default_max_body_size_mb() -> u32 {
    defaults::MAX_BODY_SIZE_MB
}
fn default_heartbeat_interval() -> u32 {
    defaults::HEARTBEAT_INTERVAL
}
fn default_heartbeat_timeout() -> u32 {
    defaults::HEARTBEAT_TIMEOUT
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            port_range_start: defaults::PORT_RANGE_START,
            port_range_end: defaults::PORT_RANGE_END,
            max_tunnels_per_client: defaults::MAX_TUNNELS_PER_CLIENT,
            default_local_addr: defaults::DEFAULT_LOCAL_ADDR.to_string(),
            public_host: String::new(),
            max_conn_per_min: defaults::MAX_CONN_PER_MIN,
            login_rate_limit: defaults::LOGIN_RATE_LIMIT,
            blacklist_threshold: defaults::BLACKLIST_THRESHOLD,
            global_whitelist: Vec::new(),
            max_body_size_mb: defaults::MAX_BODY_SIZE_MB,
            heartbeat_interval: defaults::HEARTBEAT_INTERVAL,
            heartbeat_timeout: defaults::HEARTBEAT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Authorized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceState {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub device_sign_pubkey: String,
    #[serde(default)]
    pub device_dh_pubkey: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    pub status: DeviceStatus,
    #[serde(default)]
    pub enc_key: String,
    #[serde(default)]
    pub enc_enabled: bool,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    pub first_seen: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
}

/// Server-wide shared state. All long-lived components are stored behind
/// `Arc` so the same instance is reachable from axum handlers, the WebSocket
/// task, and HTTP API tasks.
pub struct AppState {
    pub state_store: Arc<StateStore>,
    pub device_mgr: Arc<DeviceManager>,
    pub crypto_mgr: Arc<CryptoManager>,
    pub tunnel_mgr: Arc<TunnelManager>,
    pub settings: Arc<RwLock<ServerSettings>>,
    /// Active mpsc senders keyed by authorized `client_id`. Tunnel data flows
    /// through these to push encrypted frames back to the agent.
    pub authorized_senders: Arc<DashMap<String, mpsc::UnboundedSender<ServerOutMsg>>>,
    pub sessions: Arc<SessionManager>,
    pub blacklist: Arc<BlacklistManager>,
    /// Login attempts per IP per minute. 0 = disabled.
    pub login_limiter: Arc<RateLimiter>,
    /// WebSocket connection attempts per IP per minute. 0 = disabled.
    pub ws_limiter: Arc<RateLimiter>,
}

impl AppState {
    /// In-memory state — useful for tests. Use `load_or_init` when you want
    /// durable persistence via a `server-state.json` file.
    pub fn new() -> Self {
        let state_store = Arc::new(StateStore::new_in_memory());
        Self::with_store(state_store)
    }

    pub fn with_store(state_store: Arc<StateStore>) -> Self {
        let s = state_store.get_settings();
        Self::with_store_and_limits(
            state_store,
            s.login_rate_limit,
            s.max_conn_per_min,
        )
    }

    /// Like [`Self::with_store`] but lets the caller pin the rate-limit caps
    /// used to size the initial `RateLimiter`s. Tests use this to drive the
    /// limiters into a known state without rebuilding the whole stack.
    pub fn with_store_and_limits(
        state_store: Arc<StateStore>,
        login_rate_limit: u32,
        ws_rate_limit: u32,
    ) -> Self {
        let crypto_mgr = Arc::new(CryptoManager::new());
        let device_mgr = Arc::new(DeviceManager::new(
            state_store.clone(),
            crypto_mgr.clone(),
        ));
        let settings = Arc::new(RwLock::new(state_store.get_settings()));
        let mut tunnel_mgr = Arc::new(TunnelManager::new(
            crypto_mgr.clone(),
            settings.clone(),
        ));
        let authorized_senders = Arc::new(DashMap::new());
        let sessions = Arc::new(SessionManager::new());
        let blacklist = Arc::new(BlacklistManager::new(
            state_store.get_settings().blacklist_threshold,
        ));
        let login_limiter = Arc::new(RateLimiter::new(
            login_rate_limit,
            std::time::Duration::from_secs(60),
        ));
        // Same `max_conn_per_min` cap backs both the WS handler and the
        // tunnel anti-scanning limiter (Go parity: `s.portLimiter`).
        let ws_limiter = Arc::new(RateLimiter::new(
            ws_rate_limit,
            std::time::Duration::from_secs(60),
        ));
        // The tunnel manager is still uniquely owned at this point (we
        // just wrapped it in Arc a moment ago), so we can grab a
        // `&mut` to wire up the cross-component dependencies.
        Arc::get_mut(&mut tunnel_mgr)
            .expect("tunnel_mgr just constructed; no other Arc references")
            .bind_state(ws_limiter.clone(), blacklist.clone(), state_store.clone());
        Self {
            state_store,
            device_mgr,
            crypto_mgr,
            tunnel_mgr,
            settings,
            authorized_senders,
            sessions,
            blacklist,
            login_limiter,
            ws_limiter,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
