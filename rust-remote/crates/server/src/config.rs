use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "tunnel-rs-server", about = "Approval-based tunnel server")]
pub struct Config {
    /// Address to listen on, e.g. `0.0.0.0:8080`.
    #[arg(long, default_value = "0.0.0.0:8080", env = "TUNNEL_RS_ADDR")]
    pub addr: String,

    /// Directory holding `server-state.json`. The file is created on first
    /// start with a freshly generated admin password. Existing state
    /// (devices, tunnels, settings) is loaded back on subsequent starts.
    #[arg(long, default_value = "./data", env = "TUNNEL_RS_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Optional path to write the server's PID to after a successful
    /// bind. systemd Type=simple doesn't strictly need this, but it's
    /// handy for shell scripts / monit / supervisord. The file is
    /// written once at startup and left in place for the lifetime of
    /// the process; it is **not** removed on shutdown (the kernel
    /// reclaims the directory and most service managers handle
    /// cleanup).
    #[arg(long, env = "TUNNEL_RS_PIDFILE")]
    pub pidfile: Option<PathBuf>,
}

impl Config {
    pub fn parse_addr(&self) -> std::result::Result<SocketAddr, std::net::AddrParseError> {
        self.addr.parse()
    }
}
