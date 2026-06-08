use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use http::Response;
use tokio::signal;
use tower_http::trace::{MakeSpan, OnResponse, TraceLayer};
use tracing::{field, info, Span};
use tracing_subscriber::EnvFilter;

use tunnel_rs_server::{
    api,
    persist::StateStore,
    state::AppState,
    ws, Config,
};

const INDEX_HTML: &str = include_str!("../static/index.html");
const LOGIN_HTML: &str = include_str!("../static/login.html");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cfg = Config::parse();
    let addr: SocketAddr = cfg
        .parse_addr()
        .with_context(|| format!("invalid --addr: {}", cfg.addr))?;

    // ---- pidfile (write before binding so monit/supervisord can see it) ----
    if let Some(path) = &cfg.pidfile {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!("create pidfile parent dir {}", parent.display())
                })?;
            }
        }
        let pid = std::process::id();
        tokio::fs::write(path, pid.to_string().as_bytes())
            .await
            .with_context(|| format!("write pidfile {}", path.display()))?;
        info!(pidfile = %path.display(), pid, "wrote pidfile");
    }

    // ---- durable state: load or initialise server-state.json ----
    let state_path = cfg.data_dir.join("server-state.json");
    let state_store = Arc::new(
        StateStore::load_or_init(state_path.clone())
            .await
            .with_context(|| format!("initialise state at {}", state_path.display()))?,
    );
    let state = Arc::new(AppState::with_store(state_store.clone()));
    if state_store.is_read_only() {
        tracing::warn!(
            "running in READ-ONLY mode: state changes will not be persisted; \
             fix or remove the corrupt state file and restart"
        );
    }
    // Honour the configured max body size for the lifetime of the server.
    // `apply_runtime_settings` will adjust this on PUT /api/settings.
    let initial_body_limit: usize = (state
        .state_store
        .get_settings()
        .max_body_size_mb as usize)
        .saturating_mul(1024 * 1024);
    // Skip the background flush loop entirely in read-only mode — there's
    // nothing to write, and the loop would just be a busy no-op. The
    // JoinHandle is still awaited on shutdown so the early-skip path is
    // safe.
    let sync_handle = if state_store.is_read_only() {
        tokio::spawn(async move {})
    } else {
        state_store.start_sync_loop_with_handle()
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Legacy `/health` alias kept for back-compat with the Go server
        // and any external liveness probe that points at the old path.
        .route("/health", get(healthz))
        .route("/metrics", get(metrics))
        .route("/ws", get(ws::ws_handler))
        .route("/", get(index_page))
        .route("/index.html", get(index_page))
        .route("/login.html", get(login_page))
        .nest("/api", api::router(state.clone()))
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(HttpSpan)
                .on_response(HttpOnResponse),
        )
        .layer(DefaultBodyLimit::max(initial_body_limit));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!(addr = %addr, data_dir = %cfg.data_dir.display(), "tunnel-rs-server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("axum::serve")?;

    // Final flush before we drop the store — guarantees the most recent
    // state changes survive the restart even if the 3-second ticker
    // hadn't fired yet.
    state_store.stop().await;
    sync_handle.abort();
    let _ = sync_handle.await;
    info!("tunnel-rs-server stopped cleanly");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}

async fn index_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn login_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        LOGIN_HTML,
    )
}

/// Liveness probe: the process is up and the HTTP server is accepting
/// connections. Always 200 once `main` reaches the serve call. Intended
/// for Kubernetes liveness (don't restart on transient downstream issues).
async fn healthz() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "ok")
}

/// Readiness probe: state store is initialised and durable. For Phase 8
/// the state store has no external dependencies, so the same as liveness.
/// A future revision may check `state_store.path()` write-permission.
async fn readyz() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "ready")
}

/// Prometheus exposition. Renders the global registry as text/plain
/// Prometheus 0.0.4 — the format every modern scraper understands.
/// Counters / gauges are populated lazily; the endpoint is cheap to
/// hit and never blocks.
async fn metrics() -> impl IntoResponse {
    let body = tunnel_rs_server::metrics::render();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Toggle structured (JSON) output with `RUST_LOG_FORMAT=json`. Default
    // stays human-friendly for local dev. JSON mode plays nicely with
    // container log aggregators (Fluent Bit / Promtail / Cloud Logging).
    let json = matches!(
        std::env::var("RUST_LOG_FORMAT").as_deref(),
        Ok("json") | Ok("JSON")
    );
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // Route all logs to stderr so a CLI invocation with stdout
        // redirected (e.g. `> server.json`) doesn't accidentally
        // capture operational logs. Container log drivers pick up
        // stderr by default; that's the side we want here.
        .with_writer(std::io::stderr);
    if json {
        builder.json().init();
    } else {
        builder.compact().init();
    }
}

/// `tracing` span builder used by `TraceLayer`. Tags every request with a
/// unique `request_id` (UUID v4) so logs across `tower_http` and the
/// handler body can be cross-referenced.
#[derive(Clone)]
struct HttpSpan;

impl<B> MakeSpan<B> for HttpSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let request_id = uuid::Uuid::new_v4();
        tracing::info_span!(
            "http",
            method = %request.method(),
            uri = %request.uri(),
            request_id = %request_id,
            status = field::Empty,
            latency_ms = field::Empty,
        )
    }
}

/// Fills in `status` + `latency_ms` on the request span when the response
/// is produced. Keeps the log line searchable by either field.
#[derive(Clone)]
struct HttpOnResponse;

impl<B> OnResponse<B> for HttpOnResponse {
    fn on_response(self, response: &Response<B>, latency: Duration, span: &Span) {
        span.record("status", response.status().as_u16());
        span.record("latency_ms", latency.as_millis() as u64);
    }
}
