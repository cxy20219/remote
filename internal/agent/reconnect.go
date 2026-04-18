package agent

import (
	"sync"
	"time"
)

// Reconnect handles reconnection logic
type Reconnect struct {
	interval    time.Duration // initial reconnect interval
	maxAttempts int           // max attempts, 0 = infinite
	maxInterval time.Duration // max interval
	attempts    int
	mu          sync.Mutex
}

// NewReconnect creates a new Reconnect handler
func NewReconnect(interval, maxAttempts, maxInterval int) *Reconnect {
	return &Reconnect{
		interval:    time.Duration(interval) * time.Second,
		maxAttempts: maxAttempts,
		maxInterval: time.Duration(maxInterval) * time.Second,
	}
}

// shouldRetry returns true if another attempt should be made
func (r *Reconnect) shouldRetry() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.maxAttempts == 0 {
		return true
	}
	return r.attempts < r.maxAttempts
}

func (r *Reconnect) nextBackoff() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	interval := r.interval * time.Duration(1<<uint(r.attempts))
	if interval > r.maxInterval {
		interval = r.maxInterval
	}

	r.attempts++
	return interval
}

// wait sleeps for the current backoff interval
func (r *Reconnect) wait() {
	time.Sleep(r.nextBackoff())
}

// beforeRetry is called before a new connection attempt
func (r *Reconnect) beforeRetry() {
	time.Sleep(r.nextBackoff())
}

// reset resets the reconnect state
func (r *Reconnect) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = 0
}
