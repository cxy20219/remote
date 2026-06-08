//! Exponential-backoff reconnect scheduler.
//!
//! Mirrors Go's `internal/agent/reconnect.go`: start at `interval`, double
//! after each failure, cap at `max_interval`. `reset()` returns the
//! scheduler to the initial interval after a successful session.

use std::time::Duration;

pub struct Reconnect {
    interval: Duration,
    max: Duration,
    current: Duration,
    max_attempts: u32,
    attempts: u32,
}

impl Reconnect {
    pub fn new(interval: Duration, max_attempts: u32, max: Duration) -> Self {
        Self {
            interval,
            max,
            current: interval,
            max_attempts,
            attempts: 0,
        }
    }

    pub fn should_retry(&self) -> bool {
        self.max_attempts == 0 || self.attempts < self.max_attempts
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn current(&self) -> Duration {
        self.current
    }

    /// Wait the current backoff. Records the attempt.
    pub async fn wait(&mut self) {
        tokio::time::sleep(self.current).await;
        self.attempts = self.attempts.saturating_add(1);
    }

    /// Double the current backoff, clamped to `max`.
    pub fn bump(&mut self) {
        self.current = (self.current * 2).min(self.max);
    }

    /// Reset after a successful session.
    pub fn reset(&mut self) {
        self.attempts = 0;
        self.current = self.interval;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caps_at_max() {
        let mut r = Reconnect::new(Duration::from_millis(10), 100, Duration::from_millis(40));
        assert_eq!(r.current(), Duration::from_millis(10));
        r.bump();
        assert_eq!(r.current(), Duration::from_millis(20));
        r.bump();
        assert_eq!(r.current(), Duration::from_millis(40));
        r.bump();
        assert_eq!(r.current(), Duration::from_millis(40));
    }

    #[tokio::test]
    async fn zero_attempts_is_unbounded() {
        let r = Reconnect::new(Duration::from_millis(1), 0, Duration::from_millis(2));
        assert!(r.should_retry());
    }

    #[tokio::test]
    async fn reset_clears_attempts() {
        let mut r = Reconnect::new(Duration::from_millis(10), 5, Duration::from_millis(40));
        r.wait().await;
        r.wait().await;
        assert!(r.should_retry());
        r.reset();
        assert_eq!(r.attempts(), 0);
        assert_eq!(r.current(), Duration::from_millis(10));
    }
}
