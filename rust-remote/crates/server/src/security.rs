//! Rate limiters (login / ws / port), blacklist, and IP-whitelist helpers.
//!
//! All three rate limiters share the same `RateLimiter` implementation
//! (sliding 60s window keyed by IP). The blacklist is a fixed-size ring
//! of recently-blocked IPs plus a violation counter that promotes repeat
//! offenders to the global blacklist.
//!
//! Whitelists are consulted by the rate limiters (skip the check) and by
//! the port-accept loop (skip the anti-scanning limiter). Phase 4 keeps
//! the data model simple: a `Vec<String>` of CIDR/IP entries in
//! `ServerSettings.global_whitelist` plus per-device `Vec<String>` in
//! `DeviceState.ip_whitelist`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::state::{DeviceState, ServerSettings};

/// Token-bucket-ish limiter: at most `limit` events per `window` per key.
///
/// `limit` lives behind an `AtomicU32` so that the public admin endpoint
/// can tweak the cap at runtime via [`Self::set_limit`] without rebuilding
/// the limiter (Go server's `RateLimiter.SetLimit` is also hot-reload).
pub struct RateLimiter {
    inner: Arc<RwLock<Inner>>,
    limit: Arc<AtomicU32>,
    window: Duration,
}

struct Inner {
    /// Per-key sliding window of recent event timestamps.
    events: HashMap<IpAddr, VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                events: HashMap::new(),
            })),
            limit: Arc::new(AtomicU32::new(limit)),
            window,
        }
    }

    /// Update the per-window cap. The new value applies to the next
    /// [`Self::allow`] call; events already in the sliding window are kept
    /// so an in-flight burst is not retroactively accepted.
    pub fn set_limit(&self, limit: u32) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// Read the current cap. Mostly used by tests and the admin API.
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    pub fn allow(&self, key: IpAddr) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        if limit == 0 {
            return true; // disabled
        }
        let now = Instant::now();
        let mut g = self.inner.write();
        let entry = g.events.entry(key).or_default();
        // Drop expired timestamps from the front.
        while let Some(&front) = entry.front() {
            if now.duration_since(front) >= self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() as u32 >= limit {
            return false;
        }
        entry.push_back(now);
        true
    }
}

/// Blacklist: a set of blocked IPs, with an automatic "promote to global
/// blacklist" once violations reach `threshold`.
pub struct BlacklistManager {
    inner: Arc<RwLock<BlacklistInner>>,
    /// Atomic so admin can tweak the threshold at runtime via
    /// [`Self::set_threshold`] without rebuilding the manager.
    threshold: Arc<AtomicU32>,
}

#[derive(Default)]
struct BlacklistInner {
    blocked: HashSet<IpAddr>,
    violations: HashMap<IpAddr, u32>,
    /// Most recently blocked IPs, newest first. Bounded size.
    recent: VecDeque<IpAddr>,
}

impl BlacklistManager {
    pub fn new(threshold: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(BlacklistInner::default())),
            threshold: Arc::new(AtomicU32::new(threshold)),
        }
    }

    pub fn set_threshold(&self, threshold: u32) {
        self.threshold.store(threshold, Ordering::Relaxed);
    }

    pub fn threshold(&self) -> u32 {
        self.threshold.load(Ordering::Relaxed)
    }

    pub fn is_blacklisted(&self, ip: IpAddr) -> bool {
        self.inner.read().blocked.contains(&ip)
    }

    pub fn list(&self) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self.inner.read().blocked.iter().copied().collect();
        out.sort_unstable();
        out
    }

    /// Increment the per-IP violation counter. Promote to global blacklist
    /// when the counter reaches the threshold.
    pub fn add_violation(&self, ip: IpAddr) {
        let threshold = self.threshold.load(Ordering::Relaxed);
        if threshold == 0 {
            return;
        }
        let mut g = self.inner.write();
        let count = g.violations.entry(ip).or_insert(0);
        *count += 1;
        if *count >= threshold {
            g.blocked.insert(ip);
            g.recent.push_front(ip);
            while g.recent.len() > 256 {
                g.recent.pop_back();
            }
        }
    }

    pub fn add_manual(&self, ip: IpAddr) {
        let mut g = self.inner.write();
        g.blocked.insert(ip);
        g.recent.push_front(ip);
        while g.recent.len() > 256 {
            g.recent.pop_back();
        }
    }

    pub fn remove(&self, ip: IpAddr) -> bool {
        let mut g = self.inner.write();
        g.blocked.remove(&ip)
    }
}

/// IP whitelist check. Accepts exact IP and CIDR.
pub fn is_ip_whitelisted(ip: IpAddr, list: &[String]) -> bool {
    for entry in list {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(net) = entry.parse::<ipnetwork::IpNetwork>() {
            if net.contains(ip) {
                return true;
            }
        } else if let Ok(addr) = entry.parse::<IpAddr>() {
            if addr == ip {
                return true;
            }
        }
    }
    false
}

pub fn extract_ip(s: &str) -> IpAddr {
    let s = s.trim();
    // `[v6]:port` form
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        }
    }
    // v4:port — exactly one colon
    if s.matches(':').count() == 1 {
        if let Some(idx) = s.rfind(':') {
            if let Ok(ip) = s[..idx].parse::<IpAddr>() {
                return ip;
            }
        }
    }
    // Bare v6 (no port) or v4
    s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

pub fn whitelist_snapshot(settings: &ServerSettings) -> Vec<String> {
    settings.global_whitelist.clone()
}

pub fn device_whitelist(device: &DeviceState) -> Vec<String> {
    device.ip_whitelist.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rate_limiter_allows_then_blocks() {
        let l = RateLimiter::new(3, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..3 {
            assert!(l.allow(ip));
        }
        assert!(!l.allow(ip));
        // Different IP unaffected.
        assert!(l.allow(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn rate_limiter_set_limit_takes_effect_immediately() {
        let l = RateLimiter::new(0, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        // Cap=0 means "disabled"; allow should pass through.
        for _ in 0..10 {
            assert!(l.allow(ip));
        }
        // Tighten to 2 — only the next 2 should pass, the third is rejected.
        l.set_limit(2);
        assert_eq!(l.limit(), 2);
        assert!(l.allow(ip));
        assert!(l.allow(ip));
        assert!(!l.allow(ip));
    }

    #[test]
    fn rate_limiter_set_limit_keeps_inflight_burst() {
        // Hot-reload should not retroactively accept events already inside
        // the sliding window: after raising the cap, the in-flight count
        // is still checked against the new limit.
        let l = RateLimiter::new(5, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));
        for _ in 0..4 {
            assert!(l.allow(ip));
        }
        // Raise to 100 — the 4 in-flight events should not push us over.
        l.set_limit(100);
        assert!(l.allow(ip));
        // 100 minus 4 prior = 96 remaining; verify by draining.
        for _ in 0..95 {
            assert!(l.allow(ip));
        }
        assert!(!l.allow(ip));
    }

    #[test]
    fn rate_limiter_zero_is_unlimited() {
        let l = RateLimiter::new(0, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..1000 {
            assert!(l.allow(ip));
        }
    }

    #[test]
    fn blacklist_promotes_after_threshold() {
        let b = BlacklistManager::new(3);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        b.add_violation(ip);
        b.add_violation(ip);
        assert!(!b.is_blacklisted(ip));
        b.add_violation(ip);
        assert!(b.is_blacklisted(ip));
    }

    #[test]
    fn blacklist_manual_add_remove() {
        let b = BlacklistManager::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        b.add_manual(ip);
        assert!(b.is_blacklisted(ip));
        assert!(b.remove(ip));
        assert!(!b.is_blacklisted(ip));
    }

    #[test]
    fn ip_whitelist_exact_and_cidr() {
        let list = vec!["10.0.0.5".into(), "192.168.0.0/24".into()];
        assert!(is_ip_whitelisted("10.0.0.5".parse().unwrap(), &list));
        assert!(is_ip_whitelisted("192.168.0.42".parse().unwrap(), &list));
        assert!(!is_ip_whitelisted("10.0.0.6".parse().unwrap(), &list));
        assert!(!is_ip_whitelisted("172.16.0.1".parse().unwrap(), &list));
    }

    #[test]
    fn extract_ip_handles_v4_and_v6() {
        assert_eq!(
            extract_ip("10.0.0.1:8080"),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(extract_ip("10.0.0.1"), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let v6 = extract_ip("[2001:db8::1]:443");
        assert_eq!(v6, "2001:db8::1".parse::<IpAddr>().unwrap());
    }
}
