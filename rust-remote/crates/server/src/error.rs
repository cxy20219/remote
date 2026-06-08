use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

use crate::state::DeviceStatus;
use tunnel_rs_common::CommonError;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    #[error("device is not pending: {0}")]
    DeviceNotPending(String),

    #[error("device is not authorized: {0}")]
    DeviceNotAuthorized(String),

    #[error("device dh public key is required for encrypted approval")]
    DeviceMissingDhPubkey,

    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal error: {0}")]
    Internal(String),

    #[error("websocket error: {0}")]
    WebSocket(String),

    #[error(transparent)]
    Common(#[from] CommonError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

impl ServerError {
    pub fn status(&self) -> StatusCode {
        match self {
            ServerError::DeviceNotFound(_) => StatusCode::NOT_FOUND,
            ServerError::DeviceNotPending(_) | ServerError::DeviceNotAuthorized(_) => {
                StatusCode::CONFLICT
            }
            ServerError::DeviceMissingDhPubkey => StatusCode::BAD_REQUEST,
            ServerError::MethodNotAllowed(_) => StatusCode::METHOD_NOT_ALLOWED,
            ServerError::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status();
        let message = self.to_string();
        if status.is_server_error() {
            tracing::error!(error = %message, "request failed");
        } else {
            tracing::debug!(error = %message, "request rejected");
        }
        (
            status,
            Json(json!({
                "error": message,
            })),
        )
            .into_response()
    }
}

pub type Result<T> = std::result::Result<T, ServerError>;

/// Stable, wire-level label used in JSON and the persistent state file.
pub fn status_str(s: DeviceStatus) -> &'static str {
    match s {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Authorized => "authorized",
    }
}

pub fn parse_status(s: &str) -> Option<DeviceStatus> {
    match s {
        "pending" => Some(DeviceStatus::Pending),
        "authorized" => Some(DeviceStatus::Authorized),
        _ => None,
    }
}
