//! End-to-end test for the agent's connector + identity pipeline.
//!
//! Spins up the real axum server, drives a fresh agent through the
//! `register_new → approve → register_ok` flow, and verifies that the
//! per-device AES key is correctly decrypted and persisted into the
//! identity file. Then reconnects using the persisted client_id to
//! exercise the reauth path.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use futures::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tunnel_rs_agent::{connector, identity::AgentIdentity};
use tunnel_rs_common::{
    decode_dh_public_key, encode_dh_public_key, generate_dh_keypair, dh_shared_secret,
    decrypt_key_with_shared_secret,
};
use tunnel_rs_server::{api, state::AppState, ws};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_register_approve_register_ok() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(AppState::new());
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

    // ---- prepare a fresh identity ----
    let dir = TempDir::new().unwrap();
    let mut identity = AgentIdentity::load_or_create(dir.path(), &addr.to_string())
        .await
        .unwrap();
    let (_agent_dh_priv, agent_dh_pub) = generate_dh_keypair();
    // Overwrite the random DH keys with deterministic ones so the test can
    // re-derive the shared secret on the "agent" side.
    identity.device_dh_privkey = hex::encode(_agent_dh_priv.to_bytes());
    identity.device_dh_pubkey = encode_dh_public_key(&agent_dh_pub);

    // ---- first-time register: should land in pending ----
    let conn = connector::Connector::new(addr.to_string(), false);
    let (_ws, resp) = connector::register_new(&identity, &conn, "agent-host", "linux")
        .await
        .unwrap();
    let client_id = match resp {
        connector::RegisterResponse::Pending { client_id } => client_id,
        other => panic!("expected pending, got {other:?}"),
    };
    assert!(client_id.starts_with("client-"));
    // Mirror what the running agent would do: persist the pending
    // client_id so the next reload sees it.
    identity.client_id = Some(client_id.clone());
    identity.save(dir.path()).await.unwrap();

    // ---- admin approves via the device manager ----
    let (_updated, enc_key_encrypted, server_dh_pub_hex) =
        state.device_mgr.approve(&client_id).expect("approve");
    identity
        .install_enc_key(&enc_key_encrypted, &server_dh_pub_hex)
        .expect("install enc_key");
    identity.save(dir.path()).await.unwrap();
    let recovered = identity.enc_key_bytes().unwrap();
    assert_eq!(recovered.len(), 32);

    // ---- reconnect and reauth using the freshly persisted identity ----
    let identity2 = AgentIdentity::load_or_create(dir.path(), &addr.to_string())
        .await
        .unwrap();
    assert_eq!(identity2.client_id, Some(client_id.clone()));
    assert_eq!(identity2.client_id, Some(client_id.clone()));
    assert_eq!(
        identity2.enc_key.as_deref(),
        Some(hex::encode(recovered).as_str())
    );

    let conn2 = connector::Connector::new(addr.to_string(), false);
    let (_ws, resp) =
        connector::register_reauth(&identity2, &conn2, "agent-host", "linux")
            .await
            .unwrap();
    match resp {
        connector::RegisterResponse::Ok {
            client_id: cid, ..
        } => {
            assert_eq!(cid, client_id);
        }
        other => panic!("expected ok, got {other:?}"),
    }

    // ---- also exercise a delete-then-reconnect: drop the device from
    //      the server's state, then reauth. The server falls back to
    //      `register_new` (a fresh device) and assigns a new client_id
    //      that is different from the one we just deleted.
    state.device_mgr.delete(&client_id).unwrap();
    let conn3 = connector::Connector::new(addr.to_string(), false);
    let (_ws, resp) =
        connector::register_reauth(&identity2, &conn3, "agent-host", "linux")
            .await
            .unwrap();
    match resp {
        connector::RegisterResponse::Pending { client_id: cid } => {
            assert_ne!(cid, client_id, "server should have issued a new id");
        }
        other => panic!("expected pending after delete, got {other:?}"),
    }

    server.abort();
    let _ = server.await;
    drop(_ws);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_register_with_real_ws_round_trip() {
    // Spins up the server, then connects a raw tokio-tungstenite client
    // speaking the wire format. This complements the typed `register_new`
    // path and ensures the agent-side payload shape is byte-identical to
    // what the server expects.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(AppState::new());
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

    let (vk, _sk) = tunnel_rs_common::generate_sign_keypair();
    let (_dh_priv, dh_pub) = generate_dh_keypair();
    let sign_pk_hex = tunnel_rs_common::encode_verifying_key(&vk);
    let dh_pk_hex = encode_dh_public_key(&dh_pub);

    let (mut ws_tx, mut ws_rx) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap()
        .0
        .split();

    let envelope = tunnel_rs_common::message::WsMessage::with_payload(
        "register",
        serde_json::json!({
            "device_pubkey": sign_pk_hex,
            "device_dh_pubkey": dh_pk_hex,
            "hostname": "agent",
            "os": "linux",
        }),
    );
    ws_tx
        .send(Message::Text(serde_json::to_string(&envelope).unwrap()))
        .await
        .unwrap();

    let pending_text = match timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        Message::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };
    let pending: tunnel_rs_common::message::WsMessage =
        serde_json::from_str(&pending_text).unwrap();
    let client_id = pending.payload.unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Approve directly via the device manager and verify we can decrypt
    // the enc_key using our agent DH private key.
    let (_updated, enc_key_encrypted, server_dh_pub_hex) =
        state.device_mgr.approve(&client_id).expect("approve");
    let server_dh_pub = decode_dh_public_key(&server_dh_pub_hex).unwrap();
    let shared = dh_shared_secret(&_dh_priv, &server_dh_pub);
    let plain = decrypt_key_with_shared_secret(&enc_key_encrypted, &shared)
        .expect("agent must decrypt enc_key");
    assert_eq!(plain.len(), 32);

    server.abort();
    let _ = server.await;
}
