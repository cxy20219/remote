//! End-to-end tests for the admin HTTP API.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tunnel_rs_common::{
    encode_dh_public_key, encode_verifying_key, generate_dh_keypair, generate_sign_keypair,
};
use tunnel_rs_server::{api, state::AppState, ws};

async fn start_test_server() -> (SocketAddr, Arc<AppState>) {
    start_test_server_with_login_limit(0).await
}

async fn start_test_server_with_login_limit(login_limit: u32) -> (SocketAddr, Arc<AppState>) {
    use tunnel_rs_server::persist::StateStore;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_store = Arc::new(StateStore::new_in_memory());
    if login_limit > 0 {
        state_store.update_settings(|s| s.login_rate_limit = login_limit);
    }
    let state = Arc::new(AppState::with_store_and_limits(
        state_store.clone(),
        login_limit,
        0,
    ));
    let hash = tunnel_rs_server::admin_auth::hash_password("test-password").unwrap();
    state_store.set_admin_hash_for_test(hash);

    let app = Router::new()
        .route("/ws", get(ws::ws_handler))
        .route("/", get(static_index))
        .route("/index.html", get(static_index))
        .route("/login.html", get(static_login))
        .nest("/api", api::router(state.clone()))
        .with_state(state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, state)
}

/// Login and return the session token (the part of the cookie before the
/// first `;`). Tests that need to call admin endpoints must use this to
/// obtain a valid `go_remote_token`.
async fn login_token(http: &reqwest::Client, addr: SocketAddr) -> String {
    let resp = http
        .post(format!("http://{addr}/api/login"))
        .json(&json!({ "password": "test-password" }))
        .send()
        .await
        .expect("login");
    assert!(
        resp.status().is_success(),
        "login failed: {}",
        resp.status()
    );
    let cookies: Vec<_> = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    cookies
        .iter()
        .find(|c| c.starts_with("go_remote_token="))
        .expect("admin cookie")
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("go_remote_token=")
        .to_string()
}

async fn static_index() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../static/index.html").to_string(),
    )
}

async fn static_login() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../static/login.html").to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_and_admin_api_flow() {
    let (addr, state) = start_test_server().await;
    let http = reqwest::Client::new();

    // ---- login: should set the admin cookie ----
    let resp = http
        .post(format!("http://{addr}/api/login"))
        .json(&json!({ "password": "test-password" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "login status {}", resp.status());
    let cookies: Vec<_> = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let cookie = cookies
        .iter()
        .find(|c| c.starts_with("go_remote_token="))
        .expect("admin cookie");
    let token = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("go_remote_token=")
        .to_string();

    // ---- check-auth ----
    let resp = http
        .get(format!("http://{addr}/api/check-auth"))
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["authenticated"], Value::Bool(true));

    // ---- register a fake device through the device manager directly,
    //      then approve via HTTP ----
    let (vk, _sk) = generate_sign_keypair();
    let (_dh_priv, dh_pub) = generate_dh_keypair();
    let device = state
        .device_mgr
        .register_new(
            &encode_verifying_key(&vk),
            &encode_dh_public_key(&dh_pub),
            "test-host",
            "linux",
            "127.0.0.1",
        )
        .unwrap();
    let approve_url = format!(
        "http://{addr}/api/devices/pending/{}/approve",
        device.id
    );
    let resp = http
        .post(&approve_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "approve status {}", resp.status());

    // ---- update device config ----
    let cfg_url = format!("http://{addr}/api/devices/{}/config", device.id);
    let resp = http
        .put(&cfg_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .json(&json!({
            "name": "renamed",
            "enc_enabled": true,
            "ip_whitelist": ["10.0.0.0/8"]
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "renamed");
    assert_eq!(body["ip_whitelist"][0], "10.0.0.0/8");

    // ---- whitelist API (per-client) ----
    let wl_url = format!("http://{addr}/api/clients/{}/whitelist", device.id);
    let resp = http
        .put(&wl_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .json(&json!({ "ips": ["192.168.0.0/24"] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ips"][0], "192.168.0.0/24");

    // ---- blacklist add/remove ----
    let add_url = format!("http://{addr}/api/security/blacklist");
    let resp = http
        .post(&add_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .json(&json!({ "ip": "203.0.113.5" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert!(body["ips"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some("203.0.113.5")));
    let del_url = format!("http://{addr}/api/security/blacklist/203.0.113.5");
    let resp = http
        .delete(&del_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // ---- settings get/put ----
    let st_url = format!("http://{addr}/api/settings");
    let resp = http
        .get(&st_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = http
        .put(&st_url)
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .json(&json!({ "port_range_start": 25000, "port_range_end": 25100 }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["port_range_start"], 25000);

    // ---- logout invalidates the session ----
    let resp = http
        .post(format!("http://{addr}/api/logout"))
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = http
        .get(format!("http://{addr}/api/check-auth"))
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["authenticated"], Value::Bool(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn port_status_endpoint() {
    let (addr, _state) = start_test_server().await;
    let http = reqwest::Client::new();
    let token = login_token(&http, addr).await;
    let resp = http
        .get(format!("http://{addr}/api/port-status"))
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert!(body["range_start"].is_number());
    assert!(body["range_end"].is_number());
    assert!(body["total_ports"].is_number());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_pages_served_with_html_content_type() {
    let (addr, _state) = start_test_server().await;
    let http = reqwest::Client::new();
    for path in ["/", "/index.html", "/login.html"] {
        let resp = http
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{path} status {}", resp.status());
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        assert!(ct.starts_with("text/html"), "{path} content-type {ct}");
        let body = resp.text().await.unwrap();
        assert!(!body.is_empty(), "{path} should not be empty");
        assert!(body.contains("<html") || body.contains("<!DOCTYPE"), "{path} missing html doctype");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_rate_limit_blocks_after_threshold() {
    let (addr, _state) = start_test_server_with_login_limit(1).await;
    let http = reqwest::Client::new();
    let url = format!("http://{addr}/api/login");
    // First attempt burns the quota (counter is bumped before password check).
    // The wrong password is reported as 500/invalid-credentials.
    let resp1 = http
        .post(&url)
        .json(&json!({ "password": "wrong-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "first login: wrong password should 500"
    );
    let body1: Value = resp1.json().await.unwrap();
    assert!(body1["error"]
        .as_str()
        .map(|s| s.contains("invalid credentials"))
        .unwrap_or(false));
    // Second attempt from the same IP must be rate-limited.
    let resp2 = http
        .post(&url)
        .json(&json!({ "password": "wrong-2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "second login should be 500 (rate limited)"
    );
    let body: Value = resp2.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .map(|s| s.contains("rate limit"))
        .unwrap_or(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_endpoints_require_session() {
    let (addr, _state) = start_test_server().await;
    let http = reqwest::Client::new();
    let base = format!("http://{addr}");

    // No cookie at all → 401 on every admin endpoint.
    for (method, path) in [
        ("GET", "/api/devices"),
        ("GET", "/api/devices/pending"),
        ("GET", "/api/tunnels"),
        ("GET", "/api/port-status"),
        ("GET", "/api/settings"),
        ("GET", "/api/security/blacklist"),
        ("GET", "/api/security/global-whitelist"),
    ] {
        let resp = match method {
            "GET" => http.get(format!("{base}{path}")).send().await.unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{method} {path} should be 401 without session, got {}",
            resp.status()
        );
    }

    // A garbage cookie is no better than no cookie.
    let resp = http
        .get(format!("{base}/api/devices"))
        .header(reqwest::header::COOKIE, "go_remote_token=bogus")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // A wrong cookie name is also rejected — prevents the legacy
    // `tunnel_admin` name from being silently accepted.
    let resp = http
        .get(format!("{base}/api/devices"))
        .header(reqwest::header::COOKIE, "tunnel_admin=anything")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // After a real login, the admin endpoints open up.
    let resp = http
        .post(format!("{base}/api/login"))
        .json(&json!({ "password": "test-password" }))
        .send()
        .await
        .unwrap();
    let cookies: Vec<_> = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let token = cookies
        .iter()
        .find(|c| c.starts_with("go_remote_token="))
        .expect("admin cookie")
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("go_remote_token=")
        .to_string();

    let resp = http
        .get(format!("{base}/api/devices"))
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "with valid session, /api/devices should be 200"
    );

    // PUT /api/tunnels/:id is not implemented → 405 (not 500), even when
    // authenticated.
    let resp = http
        .put(format!("{base}/api/tunnels/some-tunnel"))
        .header(reqwest::header::COOKIE, format!("go_remote_token={token}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
        "PUT tunnel update should be 405, got {}",
        resp.status()
    );
}

/// Verifies that PUT /api/settings hot-reloads the rate-limit caps and
/// the blacklist threshold. Regression for the silent no-op in
/// `apply_runtime_settings` and `BlacklistManager::set_threshold`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_hot_reload_changes_limiter_caps() {
    let (addr, _state) = start_test_server().await;
    let http = reqwest::Client::new();
    let base = format!("http://{addr}");
    let token = login_token(&http, addr).await;
    let cookie = format!("go_remote_token={token}");

    // ---- 1. login limiter: tighten to 1 attempt, verify the second
    //         attempt (even with the correct password) is rejected because
    //         the quota was already burned by the wrong-password probe. ----
    let resp = http
        .put(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({ "login_rate_limit": 1 }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    // Burn the quota with a wrong password.
    let _ = http
        .post(format!("{base}/api/login"))
        .json(&json!({ "password": "wrong" }))
        .send()
        .await
        .unwrap();
    // A correct password from the same IP must now be rejected.
    let resp = http
        .post(format!("{base}/api/login"))
        .json(&json!({ "password": "test-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "expected rate limit to reject the second login"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .map(|s| s.contains("rate limit"))
        .unwrap_or(false));

    // ---- 2. blacklist threshold: tighten to 1, verify the first
    //         add_violation (via repeated blacklisting) promotes the IP. ----
    let resp = http
        .put(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({ "login_rate_limit": 100, "blacklist_threshold": 1 }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    // Single violation now promotes.
    let resp = http
        .post(format!("{base}/api/security/blacklist"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({ "ip": "203.0.113.99" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert!(body["ips"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some("203.0.113.99")));

    // ---- 3. relax everything again: login should succeed once the
    //         quota is restored to 0 (disabled). ----
    let resp = http
        .put(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({ "login_rate_limit": 0, "blacklist_threshold": 1000 }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = http
        .post(format!("{base}/api/login"))
        .json(&json!({ "password": "test-password" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "login with rate-limit=0 should pass");
}
