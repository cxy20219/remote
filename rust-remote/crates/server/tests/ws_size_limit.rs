//! Integration test for the WebSocket max-frame-size limit.
//!
//! Phase 7 优化 #8: the server must close any WebSocket connection that
//! sends a frame larger than [`tunnel_rs_common::MAX_WS_MESSAGE_SIZE`].
//! This test sends a deliberately oversized binary frame and asserts that
//! the server returns a Close frame in response.

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tunnel_rs_common::{
    encode_dh_public_key, encode_verifying_key, generate_dh_keypair, generate_sign_keypair,
    RegisterPayload, WsMessage, MAX_WS_MESSAGE_SIZE,
};
use tunnel_rs_server::{api, state::AppState, ws};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_rejects_oversized_frames() {
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

    let (mut ws_tx, mut ws_rx) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
            .await
            .unwrap()
            .0
            .split();

    // Handshake: send a real `register` first so the server treats this as
    // an authorized-style session. The server's reader only checks the size
    // cap *after* parsing the frame envelope, so any well-formed text frame
    // passes through the cap check. We follow it up with a binary frame that
    // exceeds the limit.
    let (vk, _sk) = generate_sign_keypair();
    let (_dh_priv, dh_pub) = generate_dh_keypair();
    let register = WsMessage::with_payload(
        "register",
        serde_json::to_value(RegisterPayload {
            reauth: false,
            client_id: None,
            device_pubkey: encode_verifying_key(&vk),
            device_dh_pubkey: Some(encode_dh_public_key(&dh_pub)),
            hostname: "oversize-test".into(),
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
    // Drain register_pending.
    let _ = timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .expect("register_pending")
        .expect("frame")
        .expect("ws ok");

    // Now send a binary frame that is one byte over the limit. The server
    // should close the connection in response.
    let oversized = vec![0u8; MAX_WS_MESSAGE_SIZE + 1];
    ws_tx
        .send(Message::Binary(oversized))
        .await
        .expect("send oversized frame");

    // Expect the ws stream to terminate (Close frame OR ws error OR None) — the
    // server's reader loop breaks on oversized frames and drops the
    // WebSocket, which can surface to the client as any of those signals.
    let mut terminated = false;
    for _ in 0..4 {
        match timeout(Duration::from_secs(3), ws_rx.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => {
                terminated = true;
                break;
            }
            Ok(Some(Ok(_))) => continue, // unexpected in-flight frame; keep reading
            Err(_) => break,             // read timeout — bail
        }
    }
    assert!(
        terminated,
        "server should terminate the ws after an oversized frame (limit={})",
        MAX_WS_MESSAGE_SIZE
    );

    let _ = ws_tx.send(Message::Close(None)).await;
    server.abort();
    let _ = server.await;
}
