package agent

import (
	"sync"
	"time"
)

// Reconnect handles reconnection backoff.
type Reconnect struct {
	interval    time.Duration
	maxAttempts int
	maxInterval time.Duration
	attempts    int
	mu          sync.Mutex
}

// NewReconnect creates a new Reconnect handler.
func NewReconnect(interval, maxAttempts, maxInterval int) *Reconnect {
	return &Reconnect{
		interval:    time.Duration(interval) * time.Second,
		maxAttempts: maxAttempts,
		maxInterval: time.Duration(maxInterval) * time.Second,
	}
}

// shouldRetry returns true if another attempt should be made.
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

	interval := r.interval
	if interval <= 0 {
		r.attempts++
		return interval
	}
	if r.maxInterval > 0 && interval >= r.maxInterval {
		r.attempts++
		return r.maxInterval
	}
	for i := 0; i < r.attempts; i++ {
		if r.maxInterval > 0 && interval >= r.maxInterval/2 {
			interval = r.maxInterval
			break
		}
		interval *= 2
	}
	if r.maxInterval > 0 && interval > r.maxInterval {
		interval = r.maxInterval
	}

	r.attempts++
	return interval
}

// wait sleeps for the next backoff interval. It returns false when stop is
// closed, allowing prompt shutdown instead of sleeping up to maxInterval.
func (r *Reconnect) wait(stop <-chan struct{}) bool {
	delay := r.nextBackoff()
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-stop:
		return false
	}
}

// reset resets the reconnect state.
func (r *Reconnect) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = 0
}
