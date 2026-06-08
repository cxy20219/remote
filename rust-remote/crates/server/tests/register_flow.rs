//! End-to-end test for the approval flow.
//!
//! Spins up the real axum server on a random local port, opens a WebSocket
//! from a fake agent, drives `register → approve → register_ok` and verifies
//! the ECDH-protected `enc_key` round-trips.

#![allow(clippy::result_large_err)] // tungstenite::Error is fine in test glue.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tunnel_rs_common::{
    decode_dh_public_key, decode_verifying_key, dh_shared_secret, encode_dh_public_key,
    encode_verifying_key, generate_dh_keypair, generate_sign_keypair, RegisterPayload, WsMessage,
};
use tunnel_rs_server::{api, state::AppState, ws};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_flow_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_store = Arc::new(tunnel_rs_server::persist::StateStore::new_in_memory());
    let hash = tunnel_rs_server::admin_auth::hash_password("test-password").unwrap();
    state_store.set_admin_hash_for_test(hash);
    let state = Arc::new(AppState::with_store(state_store));

    let app = Router::new()
        .route("/ws", get(ws::ws_handler))
        .nest("/api", api::router(state.clone()))
        .with_state(state.clone());

    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let http = reqwest::Client::new();
    let token = login_token(&http, addr).await;
    let cookie = format!("go_remote_token={token}");

    // ---- fake agent keys ----
    let (vk, _sk) = generate_sign_keypair();
    let (agent_dh_priv, agent_dh_pub) = generate_dh_keypair();
    let sign_pk_hex = encode_verifying_key(&vk);
    let dh_pk_hex = encode_dh_public_key(&agent_dh_pub);

    // ---- open WebSocket ----
    let url = format!("ws://{addr}/ws");
    let (mut ws_tx, mut ws_rx) = tokio_tungstenite::connect_async(&url).await.unwrap().0.split();

    // ---- send register ----
    let register = WsMessage::with_payload(
        "register",
        serde_json::to_value(RegisterPayload {
            reauth: false,
            client_id: None,
            device_pubkey: sign_pk_hex.clone(),
            device_dh_pubkey: Some(dh_pk_hex.clone()),
            hostname: "fake-agent".into(),
            os: "linux".into(),
            timestamp: None,
            signature: None,
        })
        .unwrap(),
    );
    ws_tx
        .send(Message::Text(serde_json::to_string(&register).unwrap()))
        .await
        .unwrap();

    // ---- expect register_pending ----
    let pending_text = expect_text_frame(&mut ws_rx, "register_pending").await;
    let pending_env: WsMessage = serde_json::from_str(&pending_text).unwrap();
    assert_eq!(pending_env.msg_type, "register_pending");
    let pending_payload: Value = pending_env.payload.expect("pending payload");
    let client_id = pending_payload["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    // ---- send ping to keep the connection alive ----
    let ping = WsMessage::new("ping");
    ws_tx
        .send(Message::Text(serde_json::to_string(&ping).unwrap()))
        .await
        .unwrap();
    let pong_text = expect_text_frame(&mut ws_rx, "pong").await;
    let pong_env: WsMessage = serde_json::from_str(&pong_text).unwrap();
    assert_eq!(pong_env.msg_type, "pong");

    // ---- admin approves the device over HTTP (requires session) ----
    let approve_url = format!("http://{addr}/api/devices/pending/{client_id}/approve");
    let resp = http
        .post(&approve_url)
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("http approve");
    assert!(resp.status().is_success(), "approve status {}", resp.status());
    let approve_text = resp.text().await.unwrap();
    let approve_json: Value = serde_json::from_str(&approve_text).unwrap();
    let enc_key_encrypted = approve_json["enc_key_encrypted"]
        .as_str()
        .expect("enc_key_encrypted");
    let server_dh_pub_hex = approve_json["server_dh_pubkey"]
        .as_str()
        .expect("server_dh_pubkey");

    // ---- expect register_ok over the WebSocket ----
    eprintln!("waiting for register_ok after approve");
    let ok_text = expect_text_frame(&mut ws_rx, "register_ok").await;
    eprintln!("got register_ok text: {ok_text}");
    let ok_env: WsMessage = serde_json::from_str(&ok_text).unwrap();
    assert_eq!(ok_env.msg_type, "register_ok");
    let ok_payload: Value = ok_env.payload.expect("register_ok payload");
    assert_eq!(ok_payload["client_id"].as_str(), Some(client_id.as_str()));
    assert_eq!(ok_payload["enc_enabled"].as_bool(), Some(true));
    assert_eq!(
        ok_payload["enc_key_encrypted"].as_str(),
        Some(enc_key_encrypted)
    );
    assert_eq!(
        ok_payload["server_dh_pubkey"].as_str(),
        Some(server_dh_pub_hex)
    );

    // ---- agent decrypts the enc_key using its DH private key ----
    let server_dh_pub = decode_dh_public_key(server_dh_pub_hex).unwrap();
    let shared = dh_shared_secret(&agent_dh_priv, &server_dh_pub);
    let decrypted =
        tunnel_rs_common::identity::decrypt_key_with_shared_secret(enc_key_encrypted, &shared)
            .expect("decrypt enc_key");
    assert_eq!(decrypted.len(), 32, "enc_key must be 32 bytes");

    // ---- device row reflects authorized state (requires session) ----
    let list = http
        .get(format!("http://{addr}/api/devices"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    let list_json: Value = list.json().await.unwrap();
    let devices = list_json["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["status"].as_str(), Some("authorized"));
    assert_eq!(devices[0]["id"].as_str(), Some(client_id.as_str()));
    assert_eq!(
        devices[0]["device_sign_pubkey"].as_str(),
        Some(sign_pk_hex.as_str())
    );
    // verify the stored ed25519 pubkey is real
    let _ = decode_verifying_key(devices[0]["device_sign_pubkey"].as_str().unwrap()).unwrap();

    // ---- close the socket ----
    let _ = ws_tx.send(Message::Close(None)).await;
    let _ = timeout(Duration::from_secs(1), ws_rx.next()).await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reauth_after_approve() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state_store = Arc::new(tunnel_rs_server::persist::StateStore::new_in_memory());
    let hash = tunnel_rs_server::admin_auth::hash_password("test-password").unwrap();
    state_store.set_admin_hash_for_test(hash);
    let state = Arc::new(AppState::with_store(state_store));

    let app = Router::new()
        .route("/ws", get(ws::ws_handler))
        .nest("/api", api::router(state.clone()))
        .with_state(state.clone());

    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let (vk, sk) = generate_sign_keypair();
    let (_dh_priv, dh_pub) = generate_dh_keypair();
    let sign_pk_hex = encode_verifying_key(&vk);
    let dh_pk_hex = encode_dh_public_key(&dh_pub);

    let (mut ws_tx, mut ws_rx) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap()
        .0
        .split();

    let register = WsMessage::with_payload(
        "register",
        serde_json::to_value(RegisterPayload {
            reauth: false,
            client_id: None,
            device_pubkey: sign_pk_hex.clone(),
            device_dh_pubkey: Some(dh_pk_hex.clone()),
            hostname: "fake".into(),
            os: "linux".into(),
            timestamp: None,
            signature: None,
        })
        .unwrap(),
    );
    ws_tx
        .send(Message::Text(serde_json::to_string(&register).unwrap()))
        .await
        .unwrap();
    let pending_text = expect_text_frame(&mut ws_rx, "register_pending").await;
    let pending_env: WsMessage = serde_json::from_str(&pending_text).unwrap();
    let client_id = pending_env.payload.unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let http = reqwest::Client::new();
    let token = login_token(&http, addr).await;
    let cookie = format!("go_remote_token={token}");
    http.post(format!(
        "http://{addr}/api/devices/pending/{client_id}/approve"
    ))
    .header(reqwest::header::COOKIE, &cookie)
    .send()
    .await
    .unwrap();

    let _ok_text = expect_text_frame(&mut ws_rx, "register_ok").await;
    let _ = ws_tx.send(Message::Close(None)).await;
    let _ = timeout(Duration::from_secs(1), ws_rx.next()).await;

    // ---- reconnect and reauth ----
    let (mut ws_tx2, mut ws_rx2) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap()
        .0
        .split();

    let now = chrono::Utc::now().timestamp();
    let sig = tunnel_rs_common::identity::sign_timestamp(&sk, &client_id, now);
    let sig_hex = hex::encode(sig.to_bytes());

    let reauth = WsMessage::with_payload(
        "register",
        serde_json::to_value(RegisterPayload {
            reauth: true,
            client_id: Some(client_id.clone()),
            device_pubkey: sign_pk_hex.clone(),
            device_dh_pubkey: Some(dh_pk_hex.clone()),
            hostname: "fake".into(),
            os: "linux".into(),
            timestamp: Some(now),
            signature: Some(sig_hex),
        })
        .unwrap(),
    );
    ws_tx2
        .send(Message::Text(serde_json::to_string(&reauth).unwrap()))
        .await
        .unwrap();

    let reauth_text = expect_text_frame(&mut ws_rx2, "register_ok").await;
    let env: WsMessage = serde_json::from_str(&reauth_text).unwrap();
    assert_eq!(env.msg_type, "register_ok");
    let p = env.payload.unwrap();
    assert_eq!(p["client_id"].as_str(), Some(client_id.as_str()));
    // In reauth, the server does not re-encrypt enc_key.
    assert!(p["enc_key_encrypted"].is_null());
    assert!(p["server_dh_pubkey"].is_null());

    let _ = ws_tx2.send(Message::Close(None)).await;
    let _ = timeout(Duration::from_secs(1), ws_rx2.next()).await;

    server.abort();
    let _ = server.await;
}

async fn expect_text_frame<S>(ws_rx: &mut S, expected_type: &str) -> String
where
    S: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let frame = timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {expected_type}"))
        .unwrap_or_else(|| panic!("ws stream closed waiting for {expected_type}"))
        .unwrap_or_else(|e| panic!("ws error waiting for {expected_type}: {e}"));
    match frame {
        Message::Text(t) => {
            // Sanity: payload type should match expectation.
            if let Ok(env) = serde_json::from_str::<WsMessage>(&t) {
                assert_eq!(
                    env.msg_type, expected_type,
                    "unexpected message type while waiting for {expected_type}"
                );
            }
            t
        }
        other => panic!("expected text frame for {expected_type}, got {other:?}"),
    }
}

/// Login and return the session token. Test mirrors the helper in
/// `admin_api.rs`; kept local to avoid a cross-test crate dependency.
async fn login_token(http: &reqwest::Client, addr: SocketAddr) -> String {
    let resp = http
        .post(format!("http://{addr}/api/login"))
        .json(&serde_json::json!({ "password": "test-password" }))
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
