//! HTTP API surface.
//!
//! Phase 4 exposes the Go-equivalent endpoints. Admin-only endpoints live
//! behind `auth_middleware`, which checks a `tunnel_admin` cookie against
//! the in-memory session store. Public endpoints: `/health`, `/api/login`,
//! `/api/logout`, and the WebSocket.

use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tunnel_rs_common::message::{RegisterOkPayload, WsMessage};

use crate::device_mgr::ServerOutMsg;
use crate::error::{Result, ServerError};
use crate::security;
use crate::state::{AppState, DeviceState, DeviceStatus, ServerSettings};
use crate::tunnel::TunnelExposure;

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    // Public routes — accessible without a session.
    let public = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/check-auth", get(check_auth));

    // Admin routes — guarded by `require_session` middleware. Any request
    // without a valid `go_remote_token` session cookie gets 401.
    let admin = Router::new()
        // Devices
        .route("/devices", get(list_devices))
        .route("/devices/pending", get(list_pending))
        .route("/devices/pending/:id/approve", post(approve))
        .route("/devices/pending/:id/deny", post(deny))
        .route("/devices/:id", axum::routing::delete(delete_device))
        .route("/devices/:id/config", axum::routing::put(update_device_config))
        .route("/devices/:id/regen-key", axum::routing::put(regen_device_key))
        // Per-client IP whitelist (legacy path kept for parity with Go)
        .route("/clients/:id/whitelist", get(get_client_whitelist))
        .route(
            "/clients/:id/whitelist",
            axum::routing::put(put_client_whitelist),
        )
        // Tunnels
        .route("/tunnels", get(list_tunnels).post(create_tunnel))
        .route("/tunnels/:tunnel_id", get(get_tunnel))
        .route("/tunnels/:tunnel_id", axum::routing::delete(delete_tunnel))
        .route("/tunnels/:tunnel_id", axum::routing::put(update_tunnel))
        .route(
            "/client-tunnels/:client_id",
            get(list_client_tunnels),
        )
        .route("/port-status", get(port_status))
        // Security
        .route(
            "/security/global-whitelist",
            get(get_global_whitelist).put(put_global_whitelist),
        )
        .route(
            "/security/blacklist",
            get(get_blacklist).post(add_blacklist),
        )
        .route(
            "/security/blacklist/:ip",
            axum::routing::delete(remove_blacklist),
        )
        .route(
            "/security/blacklist-threshold",
            get(get_blacklist_threshold).put(put_blacklist_threshold),
        )
        // Settings
        .route("/settings", get(get_settings).put(put_settings))
        .route_layer(from_fn_with_state(state.clone(), require_session));

    public.merge(admin).with_state(state)
}

/// Auth middleware: any handler behind this layer requires a valid
/// `go_remote_token` session. Invalid or missing cookie → 401.
async fn require_session(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> std::result::Result<Response, ServerError> {
    if !has_valid_session(&state, &headers) {
        return Err(ServerError::Unauthorized);
    }
    Ok(next.run(request).await)
}

// ---------- system ----------
// /health is registered in `main.rs` as an inline closure that returns
// "ok" — no need for a dedicated handler here.

// ---------- auth ----------

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse> {
    if !state.login_limiter.allow(remote.ip()) {
        return Err(ServerError::Internal("rate limit exceeded".into()));
    }
    if !state.state_store.verify_admin_password(&body.password) {
        return Err(ServerError::Internal("invalid credentials".into()));
    }
    let token = state.sessions.issue();
    let cookie = format!(
        "{}={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400",
        crate::session::SESSION_COOKIE,
        token
    );
    Ok(([(axum::http::header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(cookie) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix(&format!("{}=", crate::session::SESSION_COOKIE))
            {
                state.sessions.revoke(rest);
            }
        }
    }
    let clear = format!(
        "{}=; HttpOnly; Path=/; Max-Age=0",
        crate::session::SESSION_COOKIE
    );
    (
        [(axum::http::header::SET_COOKIE, clear)],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

async fn check_auth(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    Json(json!({ "authenticated": has_valid_session(&state, &headers) }))
}

fn has_valid_session(state: &Arc<AppState>, headers: &axum::http::HeaderMap) -> bool {
    let Some(cookie) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    cookie
        .split(';')
        .filter_map(|p| p.trim().strip_prefix(&format!("{}=", crate::session::SESSION_COOKIE)))
        .any(|tok| state.sessions.validate(tok))
}

// ---------- devices ----------

async fn list_devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "devices": state.state_store.list_devices() }))
}

async fn list_pending(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "devices": state.state_store.list_devices_by_status(DeviceStatus::Pending)
    }))
}

async fn approve(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<axum::response::Response> {
    let (device, enc_key_encrypted, server_dh_pubkey) = state.device_mgr.approve(&id)?;
    let pending = state.device_mgr.take_pending_conn(&id);
    if let Some(p) = pending {
        let payload = RegisterOkPayload {
            client_id: device.id.clone(),
            enc_key_encrypted: Some(enc_key_encrypted.clone()),
            server_dh_pubkey: Some(server_dh_pubkey.clone()),
            enc_enabled: device.enc_enabled,
        };
        let value = serde_json::to_value(&payload).map_err(ServerError::from)?;
        let text = serde_json::to_string(&WsMessage::with_payload("register_ok", value))
            .map_err(ServerError::from)?;
        let _ = p.tx.send(ServerOutMsg::Text(text));
    } else {
        tracing::warn!(device_id = %id, "approved device has no live pending conn");
    }
    Ok((
        StatusCode::OK,
        Json(json!({
            "device": device,
            "enc_key_encrypted": enc_key_encrypted,
            "server_dh_pubkey": server_dh_pubkey,
        })),
    )
        .into_response())
}

async fn deny(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    state.device_mgr.deny(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    state.device_mgr.delete(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_device_config(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<UpdateDeviceConfigRequest>,
) -> Result<Json<DeviceState>> {
    let device = state.device_mgr.update_config(
        &id,
        body.name,
        body.enc_enabled,
        body.ip_whitelist,
    )?;
    Ok(Json(device))
}

async fn regen_device_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let key = state.device_mgr.regenerate_enc_key(&id)?;
    Ok(Json(json!({ "enc_key": hex::encode(key) })))
}

async fn get_client_whitelist(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let list = state.device_mgr.get_ip_whitelist(&id)?;
    Ok(Json(json!({ "ips": list })))
}

async fn put_client_whitelist(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<WhitelistRequest>,
) -> Result<Json<Value>> {
    let device = state.device_mgr.set_ip_whitelist(&id, body.ips.clone())?;
    Ok(Json(json!({ "ips": device.ip_whitelist })))
}

// ---------- tunnels ----------

async fn list_tunnels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tunnels: Vec<Value> = state
        .tunnel_mgr
        .list_tunnels()
        .iter()
        .map(|t| tunnel_to_json(t))
        .collect();
    Json(json!({ "tunnels": tunnels }))
}

async fn get_tunnel(
    State(state): State<Arc<AppState>>,
    Path(tunnel_id): Path<String>,
) -> Result<Json<Value>> {
    let t = state
        .tunnel_mgr
        .get_tunnel(&tunnel_id)
        .ok_or_else(|| ServerError::Internal(format!("tunnel {tunnel_id} not found")))?;
    Ok(Json(tunnel_to_json(&t)))
}

async fn list_client_tunnels(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    let tunnels: Vec<Value> = state
        .tunnel_mgr
        .list_tunnels_by_client(&client_id)
        .iter()
        .map(|t| tunnel_to_json(t))
        .collect();
    Json(json!({ "tunnels": tunnels }))
}

async fn create_tunnel(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateTunnelRequest>,
) -> Result<axum::response::Response> {
    let exposure = TunnelExposure::parse(&body.exposure.clone().unwrap_or_else(|| "public".into()))
        .map_err(ServerError::Internal)?;
    let device = state
        .state_store
        .get_device(&body.client_id)
        .ok_or_else(|| ServerError::Internal(format!("client {} not found", body.client_id)))?;
    if !matches!(device.status, DeviceStatus::Authorized) {
        return Err(ServerError::Internal(format!(
            "client {} is not authorized",
            body.client_id
        )));
    }
    // Enforce the per-client tunnel cap. Set to 0 to disable the limit
    // (useful for development / load tests).
    let max_tunnels_per_client = state.settings.read().max_tunnels_per_client;
    if max_tunnels_per_client > 0 {
        let active = state
            .tunnel_mgr
            .list_tunnels_by_client(&device.id)
            .len();
        if (active as u32) >= max_tunnels_per_client {
            return Err(ServerError::Internal(format!(
                "client {} already has {} active tunnels (limit {})",
                device.id, active, max_tunnels_per_client
            )));
        }
    }
    let sender = state
        .authorized_senders
        .get(&device.id)
        .map(|s| s.clone())
        .ok_or_else(|| {
            ServerError::Internal(format!(
                "client {} has no live authorized conn",
                body.client_id
            ))
        })?;
    let tunnel_id = body
        .tunnel_id
        .clone()
        .unwrap_or_else(|| format!("tunnel-{}", uuid::Uuid::new_v4().simple()));
    let port = state
        .tunnel_mgr
        .create_tunnel(
            tunnel_id.clone(),
            body.client_id.clone(),
            sender,
            body.local_addr.clone().unwrap_or_else(|| "127.0.0.1".into()),
            body.local_port,
            exposure,
        )
        .await
        .map_err(ServerError::Internal)?;
    let tunnel = state
        .tunnel_mgr
        .get_tunnel(&tunnel_id)
        .ok_or_else(|| ServerError::Internal("tunnel vanished after create".into()))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "tunnel_id": tunnel_id,
            "public_port": port,
            "public_addr": format!("{}:{}", state.state_store.get_settings().public_host, port),
            "access_addr": format!("{}:{}", state.state_store.get_settings().public_host, port),
            "exposure": exposure.as_str(),
            "local_addr": body.local_addr.unwrap_or_else(|| "127.0.0.1".into()),
            "status": "active",
            "tunnel": tunnel_to_json(&tunnel),
        })),
    )
        .into_response())
}

async fn delete_tunnel(
    State(state): State<Arc<AppState>>,
    Path(tunnel_id): Path<String>,
) -> Result<StatusCode> {
    state
        .tunnel_mgr
        .close_tunnel(&tunnel_id)
        .await
        .map_err(ServerError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_tunnel(
    State(_state): State<Arc<AppState>>,
    Path(_tunnel_id): Path<String>,
    Json(_body): Json<Value>,
) -> Result<StatusCode> {
    // Phase 5/7 can implement; the agent doesn't currently use it. Return
    // 405 (not 500) so the front-end gets a clear "method not supported"
    // signal instead of an opaque internal error.
    Err(ServerError::MethodNotAllowed(
        "tunnel update is not yet implemented".into(),
    ))
}

async fn port_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let s = state.tunnel_mgr.port_status();
    Json(json!({
        "range_start": s.range_start,
        "range_end": s.range_end,
        "total_ports": s.total,
        "allocated": s.allocated,
        "unavailable": s.unavailable,
        "available_count": (s.total as usize).saturating_sub(s.allocated).saturating_sub(s.unavailable.len()),
    }))
}

// ---------- security ----------

async fn get_global_whitelist(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "ips": security::whitelist_snapshot(&state.state_store.get_settings()) }))
}

async fn put_global_whitelist(
    State(state): State<Arc<AppState>>,
    Json(body): Json<WhitelistRequest>,
) -> Result<Json<Value>> {
    let deduped = dedup_ips(body.ips.clone());
    state.state_store.update_settings(|s| s.global_whitelist = deduped.clone());
    Ok(Json(json!({ "ips": deduped })))
}

async fn get_blacklist(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({ "ips": state.blacklist.list() }))
}

async fn add_blacklist(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BlacklistAddRequest>,
) -> Result<Json<Value>> {
    let ip = body
        .ip
        .parse()
        .map_err(|_| ServerError::Internal(format!("invalid ip: {}", body.ip)))?;
    state.blacklist.add_manual(ip);
    Ok(Json(json!({ "ips": state.blacklist.list() })))
}

async fn remove_blacklist(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<StatusCode> {
    let parsed = ip
        .parse()
        .map_err(|_| ServerError::Internal(format!("invalid ip: {ip}")))?;
    if !state.blacklist.remove(parsed) {
        return Err(ServerError::Internal(format!("{ip} not in blacklist")));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn get_blacklist_threshold(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let s = state.state_store.get_settings();
    Json(json!({ "threshold": s.blacklist_threshold }))
}

async fn put_blacklist_threshold(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ThresholdRequest>,
) -> Result<Json<Value>> {
    state
        .state_store
        .update_settings(|s| s.blacklist_threshold = body.threshold);
    let s = state.state_store.get_settings();
    Ok(Json(json!({ "threshold": s.blacklist_threshold })))
}

// ---------- settings ----------

async fn get_settings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::to_value(state.state_store.get_settings()).unwrap_or(Value::Null))
}

async fn put_settings(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ServerSettings>,
) -> Result<Json<ServerSettings>> {
    state
        .state_store
        .update_settings(|s| *s = body.clone());
    apply_runtime_settings(&state, &body);
    Ok(Json(state.state_store.get_settings()))
}

fn apply_runtime_settings(state: &Arc<AppState>, s: &ServerSettings) {
    state
        .tunnel_mgr
        .set_port_range(s.port_range_start, s.port_range_end);
    // Hot-reload the rate-limit caps. `RateLimiter` keeps an internal
    // `AtomicU32`, so this is a single relaxed store; the limiter
    // consults the live value on every `allow()` call.
    state.login_limiter.set_limit(s.login_rate_limit);
    state.ws_limiter.set_limit(s.max_conn_per_min);
    // Same hot-reload pattern for the violation threshold that promotes
    // repeat offenders to the global blacklist.
    state.blacklist.set_threshold(s.blacklist_threshold);
}

// ---------- helpers ----------

fn dedup_ips(ips: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        let ip = ip.trim().to_string();
        if ip.is_empty() || !seen.insert(ip.clone()) {
            continue;
        }
        out.push(ip);
    }
    out
}

fn tunnel_to_json(t: &crate::tunnel::Tunnel) -> Value {
    json!({
        "tunnel_id": t.tunnel_id,
        "client_id": t.client_id,
        "public_port": t.public_port,
        "exposure": t.exposure.as_str(),
        "bind_addr": t.bind_addr.to_string(),
        "local_addr": t.local_addr,
        "local_port": t.local_port,
        "status": match t.status {
            crate::tunnel::TunnelStatus::Active => "active",
            crate::tunnel::TunnelStatus::Closing => "closing",
        },
        "created_at": t.created_at,
    })
}

// ---------- request types ----------

#[derive(Debug, Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct UpdateDeviceConfigRequest {
    name: Option<String>,
    enc_enabled: Option<bool>,
    ip_whitelist: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct WhitelistRequest {
    ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BlacklistAddRequest {
    ip: String,
}

#[derive(Debug, Deserialize)]
struct ThresholdRequest {
    threshold: u32,
}

#[derive(Debug, Deserialize)]
struct CreateTunnelRequest {
    client_id: String,
    local_addr: Option<String>,
    local_port: u16,
    exposure: Option<String>,
    tunnel_id: Option<String>,
}
