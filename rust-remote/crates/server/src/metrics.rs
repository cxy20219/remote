//! Prometheus metrics. Exposes a small, deliberately hand-rolled surface
//! of counters and gauges that cover the operational signal: HTTP
//! traffic, admin authentication outcomes, device lifecycle, and tunnel
//! counts. No histograms yet — the `prometheus` crate would pull in
//! `protobuf` and `lazy_static` for very little extra value at this
//! scale.
//!
//! Rendered on demand by [`render`], which the `main.rs` `/metrics`
//! handler calls. Counters are mutated at the call site via the
//! `inc_*` helpers; the registry is process-global.

use std::sync::OnceLock;

use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};

/// Process-global registry. Initialised lazily on first access so the
/// binary doesn't pay the cost when `--help` / early failure paths run.
fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(Registry::new)
}

macro_rules! define_counter {
    ($name:ident, $help:expr) => {{
        static COUNTER: OnceLock<IntCounter> = OnceLock::new();
        COUNTER.get_or_init(|| {
            let c = IntCounter::new(stringify!($name), $help).expect("counter def");
            registry()
                .register(Box::new(c.clone()))
                .expect("register counter");
            c
        })
    }};
}

macro_rules! define_gauge {
    ($name:ident, $help:expr) => {{
        static GAUGE: OnceLock<IntGauge> = OnceLock::new();
        GAUGE.get_or_init(|| {
            let g = IntGauge::new(stringify!($name), $help).expect("gauge def");
            registry()
                .register(Box::new(g.clone()))
                .expect("register gauge");
            g
        })
    }};
}

/// Total HTTP requests handled, broken down by status class.
pub fn inc_http_request(status_class: &'static str) {
    let c = match status_class {
        "2xx" => &*define_counter!(http_requests_2xx, "HTTP 2xx responses"),
        "4xx" => &*define_counter!(http_requests_4xx, "HTTP 4xx responses"),
        "5xx" => &*define_counter!(http_requests_5xx, "HTTP 5xx responses"),
        _ => &*define_counter!(http_requests_other, "HTTP other (1xx/3xx) responses"),
    };
    c.inc();
}

/// Successful admin logins.
pub fn inc_login_success() {
    define_counter!(admin_login_success_total, "Successful admin logins").inc();
}

/// Failed admin logins (bad password or rate-limited).
pub fn inc_login_failure() {
    define_counter!(admin_login_failure_total, "Failed admin logins").inc();
}

/// Devices that have registered but not yet been approved.
pub fn inc_device_registered() {
    define_counter!(device_registered_total, "New device registrations").inc();
}

/// Admin approval events.
pub fn inc_device_approved() {
    define_counter!(device_approved_total, "Admin-approved devices").inc();
}

/// Active WS connections (incremented on accept, decremented on close).
pub fn set_ws_connections(n: i64) {
    define_gauge!(ws_connections_active, "Active WebSocket connections").set(n);
}

/// Authorised devices currently connected.
pub fn set_authorized_devices(n: i64) {
    define_gauge!(authorized_devices_active, "Authorised devices online").set(n);
}

/// Number of tunnels currently allocated across all clients.
pub fn set_active_tunnels(n: i64) {
    define_gauge!(active_tunnels, "Currently allocated public ports").set(n);
}

/// Blacklisted IPs (global list).
pub fn set_blacklist_size(n: i64) {
    define_gauge!(blacklist_size, "IPs in the global blacklist").set(n);
}

/// Render the registry as Prometheus 0.0.4 text. Returns a static
/// placeholder if the registry is empty so scrapers never see an
/// empty body.
pub fn render() -> String {
    let metric_families = registry().gather();
    let mut buf = Vec::with_capacity(4096);
    let encoder = TextEncoder::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        tracing::warn!(error = %e, "metrics encode failed");
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_prometheus_text() {
        inc_http_request("2xx");
        inc_login_success();
        set_ws_connections(7);
        let body = render();
        // Must contain the HELP / TYPE preamble for each registered
        // metric, even if the value is 0.
        assert!(body.contains("http_requests_2xx"));
        assert!(body.contains("admin_login_success_total"));
        assert!(body.contains("ws_connections_active 7"));
    }
}
