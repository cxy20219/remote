package agent

import (
	"math/rand/v2"
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

// jitterBackoff 给退避时间加 ±20% 的抖动，均匀落在 [0.8d, 1.2d)。
//
// 不加抖动的指数退避是确定性的：服务端发版重启后，所有设备会在同一秒重连、
// 同一秒 reauth、同一秒重放 tunnel_open，设备越多越像雪崩。抖动把重连峰摊开，
// 代价只是单个设备的重连间隔有一点随机性。
func jitterBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	factor := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(d) * factor)
}

// nextBackoff 返回本次退避时长（已加抖动）。
//
// 抖动加在封顶之后，所以这里要再夹一次：否则 60s 的上限会被 1.2 倍放大到 72s，
// 「最长等 60 秒」这句配置说明就不成立了。
func (r *Reconnect) nextBackoff() time.Duration {
	jittered := jitterBackoff(r.baseBackoff())

	r.mu.Lock()
	maxInterval := r.maxInterval
	r.mu.Unlock()

	if maxInterval > 0 && jittered > maxInterval {
		return maxInterval
	}
	return jittered
}

// baseBackoff 是不含抖动的退避：固定起始间隔、指数翻倍、maxInterval 封顶。
func (r *Reconnect) baseBackoff() time.Duration {
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
