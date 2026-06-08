//! Agent CLI configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser, Clone)]
#[command(name = "tunnel-rs-agent", about = "GoRemote-compatible agent")]
pub struct Config {
    /// Server address (host:port).
    pub server: String,

    /// Directory holding the persistent identity file.
    #[arg(long, env = "TUNNEL_RS_IDENTITY_DIR")]
    pub identity_dir: Option<PathBuf>,

    /// Connect with TLS (wss://).
    #[arg(long, default_value_t = false)]
    pub tls: bool,

    /// Skip TLS certificate verification (insecure, dev only).
    #[arg(long, default_value_t = false)]
    pub insecure_skip_verify: bool,

    /// Optional CA bundle for server certificate validation.
    #[arg(long)]
    pub tls_ca: Option<PathBuf>,

    /// Heartbeat interval in seconds.
    #[arg(long, default_value_t = 30)]
    pub heartbeat_interval: u64,

    /// Initial reconnect interval in seconds.
    #[arg(long, default_value_t = 5)]
    pub reconnect_interval: u64,

    /// Maximum reconnect interval in seconds.
    #[arg(long, default_value_t = 60)]
    pub reconnect_max: u64,
}

impl Config {
    pub fn identity_dir(&self) -> PathBuf {
        self.identity_dir.clone().unwrap_or_else(crate::identity::default_identity_dir)
    }

    pub fn server_addr(&self) -> &str {
        &self.server
    }

    /// Parse the server address as a SocketAddr. Returns the raw `host:port`
    /// string if it isn't a plain `SocketAddr` (Go-style "host:port" without
    /// an explicit port is rejected here).
    pub fn parse_addr(&self) -> std::result::Result<SocketAddr, std::net::AddrParseError> {
        self.server.parse()
    }
}
