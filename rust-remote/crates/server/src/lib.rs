//! Tunnel server: state store, device manager, WebSocket handler, HTTP API.
//!
//! This crate is structured as a library + binary so that integration tests
//! can spin up the real axum router without re-implementing the routing.

pub mod admin_auth;
pub mod api;
pub mod config;
pub mod device_mgr;
pub mod error;
pub mod metrics;
pub mod persist;
pub mod security;
pub mod session;
pub mod state;
pub mod tunnel;
pub mod ws;

pub use config::Config;
pub use error::{Result, ServerError};
pub use state::{AppState, DeviceState, DeviceStatus, ServerSettings};
