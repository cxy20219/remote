//! End-to-end test for the tunnel data path.
//!
//! Spins up the real axum server, drives `register → approve` over the
//! WebSocket and HTTP, then creates a tunnel, connects a "public" client
//! to the allocated port, and verifies the round-trip through the fake
//! agent (which simply echoes every received payload back).

#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tunnel_rs_common::{
    decode_frame, encode_frame, encode_dh_public_key, encode_verifying_key, generate_dh_keypair,
    generate_sign_keypair, RegisterPayload, WsMessage,
};
use tunnel_rs_server::{api, state::AppState, ws};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_echo_round_trip() {
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

    // ---- fake agent keys ----
    let (vk, _sk) = generate_sign_keypair();
    let (_dh_priv, dh_pub) = generate_dh_keypair();
    let sign_pk_hex = encode_verifying_key(&vk);
    let dh_pk_hex = encode_dh_public_key(&dh_pub);

    // ---- agent: open WS, register (pending), ping to drive transition ----
    let (mut agent_tx, mut agent_rx) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
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
            hostname: "agent".into(),
            os: "linux".into(),
            timestamp: None,
            signature: None,
        })
        .unwrap(),
    );
    agent_tx
        .send(Message::Text(serde_json::to_string(&register).unwrap()))
        .await
        .unwrap();
    let pending_text = expect_text(&mut agent_rx, "register_pending").await;
    let pending_env: WsMessage = serde_json::from_str(&pending_text).unwrap();
    let client_id = pending_env.payload.unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    // ---- admin approves the device directly via the device manager ----
    let (_updated, _enc, _dh) = state
        .device_mgr
        .approve(&client_id)
        .expect("approve");
    // Replace the auto-generated key with a known one for round-trip tests.
    state.crypto_mgr.set_key(&client_id, &[0xAB; 32]).unwrap();

    // ---- drive a few ping/pong exchanges so the server-side session
    //      notices the pending→authorized transition ----
    for _ in 0..3 {
        let ping = WsMessage::new("ping");
        agent_tx
            .send(Message::Text(serde_json::to_string(&ping).unwrap()))
            .await
            .unwrap();
        let _ = expect_text(&mut agent_rx, "pong").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // ---- agent sends tunnel_open ----
    let tunnel_id = "t-echo";
    let tunnel_open = WsMessage::with_payload(
        "tunnel_open",
        serde_json::json!({
            "tunnel_id": tunnel_id,
            "local_addr": "127.0.0.1",
            "local_port": 22,
            "protocol": "server_local",
        }),
    );
    agent_tx
        .send(Message::Text(
            serde_json::to_string(&tunnel_open).unwrap(),
        ))
        .await
        .unwrap();
    let ack_text = expect_text(&mut agent_rx, "tunnel_open_ack").await;
    let ack: WsMessage = serde_json::from_str(&ack_text).unwrap();
    let ack_payload: TunnelOpenAck = serde_json::from_value(ack.payload.unwrap()).unwrap();
    assert!(ack_payload.success, "ack: {ack_payload:?}");
    let public_port = ack_payload.public_port;
    assert!(public_port > 0);

    // ---- agent runs an echo loop on its own task ----
    let crypto = state.crypto_mgr.clone();
    let client_id_for_echo = client_id.clone();
    let agent_task = tokio::spawn(async move {
        while let Some(msg) = agent_rx.next().await {
            let Ok(msg) = msg else { break };
            match msg {
                Message::Binary(bin) => {
                    let frame = match decode_frame(&bin) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    if frame.is_eof {
                        continue;
                    }
                    let plain = match crypto.decrypt(&client_id_for_echo, &frame.data) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let ct = crypto.encrypt(&client_id_for_echo, &plain).unwrap();
                    let out = encode_frame(&frame.tunnel_id, &frame.conn_id, &ct, false).unwrap();
                    if agent_tx.send(Message::Binary(out)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // ---- public client connects to the tunnel's public port ----
    let mut public = TcpStream::connect(("127.0.0.1", public_port))
        .await
        .expect("connect to public port");
    use tokio::io::AsyncWriteExt;
    public.write_all(b"hello world").await.unwrap();

    // ---- the public side should receive the echo back ----
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(2), public.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read error");
    assert_eq!(&buf[..n], b"hello world", "echo must match");

    // ---- close the public side; the server should drop the ext conn ----
    drop(public);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Cleanup
    agent_task.abort();
    let _ = agent_task.await;
    server.abort();
    let _ = server.await;
}

#[derive(Debug, serde::Deserialize)]
struct TunnelOpenAck {
    #[allow(dead_code)]
    tunnel_id: String,
    public_port: u16,
    success: bool,
    #[serde(default)]
    #[allow(dead_code)]
    error: Option<String>,
}

async fn expect_text<S>(ws_rx: &mut S, expected: &str) -> String
where
    S: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let frame = timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for {expected}"))
        .unwrap_or_else(|| panic!("ws stream closed waiting for {expected}"))
        .unwrap_or_else(|e| panic!("ws error waiting for {expected}: {e}"));
    match frame {
        Message::Text(t) => {
            if let Ok(env) = serde_json::from_str::<WsMessage>(&t) {
                assert_eq!(
                    env.msg_type, expected,
                    "unexpected message type while waiting for {expected}"
                );
            }
            t
        }
        other => panic!("expected text frame for {expected}, got {other:?}"),
    }
}

// Make sure serde_json::Value is "used" even if the test changes shape.
#[allow(dead_code)]
fn _ensure_value(_: &Value) {}
