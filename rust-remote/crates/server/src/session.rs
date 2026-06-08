//! Admin session management.
//!
//! Sessions are tracked in-memory: opaque random tokens mapped to an
//! expiry instant. A 24h lifetime is the default; up to 64 sessions are
//! retained and pruned lazily on insert.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;

pub const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const SESSION_MAX: usize = 64;
/// Cookie name. Matches the Go server's `go_remote_token` so the two
/// implementations stay inter-operable.
pub const SESSION_COOKIE: &str = "go_remote_token";

#[derive(Clone)]
struct SessionRecord {
    created_at: Instant,
    expires_at: Instant,
}

pub struct SessionManager {
    inner: Arc<RwLock<HashMap<String, SessionRecord>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn issue(&self) -> String {
        let token = random_token();
        let now = Instant::now();
        let mut g = self.inner.write();
        g.insert(
            token.clone(),
            SessionRecord {
                created_at: now,
                expires_at: now + SESSION_TTL,
            },
        );
        // Cap memory by dropping the oldest sessions.
        while g.len() > SESSION_MAX {
            if let Some(oldest) = g
                .iter()
                .min_by_key(|(_, v)| v.created_at)
                .map(|(k, _)| k.clone())
            {
                g.remove(&oldest);
            } else {
                break;
            }
        }
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        let g = self.inner.read();
        matches!(g.get(token), Some(r) if r.expires_at > Instant::now())
    }

    pub fn revoke(&self, token: &str) {
        self.inner.write().remove(token);
    }

    /// Force a previously-issued token to be considered expired the next
    /// time [`Self::validate`] is called. Returns `true` if the token was
    /// found and expired; `false` otherwise. Named with a `_for_test`
    /// suffix to make the intent obvious — production code paths should
    /// never need to forge expiry, and the 24-hour lifetime is the only
    /// mechanism real users ever hit.
    pub fn expire_for_test(&self, token: &str) -> bool {
        let mut g = self.inner.write();
        if let Some(r) = g.get_mut(token) {
            r.expires_at = Instant::now() - Duration::from_secs(1);
            true
        } else {
            false
        }
    }

    pub fn gc_expired(&self) {
        let now = Instant::now();
        self.inner.write().retain(|_, r| r.expires_at > now);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    // OS CSPRNG: 256-bit session tokens don't need to be reseed-protected,
    // and `OsRng` is the canonical source for fresh cryptographic material.
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_validate() {
        let m = SessionManager::new();
        let t = m.issue();
        assert!(m.validate(&t));
    }

    #[test]
    fn revoke_invalidates() {
        let m = SessionManager::new();
        let t = m.issue();
        m.revoke(&t);
        assert!(!m.validate(&t));
    }

    #[test]
    fn unknown_token_is_invalid() {
        let m = SessionManager::new();
        assert!(!m.validate("nope"));
    }

    #[test]
    fn cap_keeps_most_recent() {
        let m = SessionManager::new();
        let mut issued = Vec::new();
        for _ in 0..(SESSION_MAX + 5) {
            issued.push(m.issue());
        }
        // The most recent ones are still valid.
        for t in issued.iter().rev().take(5) {
            assert!(m.validate(t), "recently-issued session dropped");
        }
    }
}
