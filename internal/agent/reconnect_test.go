package agent

import (
	"testing"
	"time"
)

func TestReconnectBeforeRetryIncrementsAttempts(t *testing.T) {
	r := NewReconnect(0, 3, 0)

	r.wait(nil)
	if r.attempts != 1 {
		t.Fatalf("expected attempts to be 1 after first retry, got %d", r.attempts)
	}

	r.wait(nil)
	if r.attempts != 2 {
		t.Fatalf("expected attempts to be 2 after second retry, got %d", r.attempts)
	}
}

func TestReconnectResetClearsAttempts(t *testing.T) {
	r := NewReconnect(0, 2, 0)

	r.wait(nil)
	r.wait(nil)
	if r.shouldRetry() {
		t.Fatal("expected retry budget to be exhausted before reset")
	}

	r.reset()
	if !r.shouldRetry() {
		t.Fatal("expected retry budget to be restored after reset")
	}
	if r.attempts != 0 {
		t.Fatalf("expected attempts to reset to 0, got %d", r.attempts)
	}
}

// jitterRange 断言退避落在 [0.8d, 1.2d] 内；给 cap 时上界不超过 cap（封顶后夹紧）。
func jitterRange(t *testing.T, got, base time.Duration, cap ...time.Duration) {
	t.Helper()
	low := time.Duration(float64(base) * 0.8)
	high := time.Duration(float64(base) * 1.2)
	if len(cap) > 0 && cap[0] > 0 && high > cap[0] {
		high = cap[0]
	}
	if got < low || got > high {
		t.Fatalf("backoff %v outside the jitter band [%v, %v]", got, low, high)
	}
}

func TestReconnectNextBackoffHonorsMaxInterval(t *testing.T) {
	r := NewReconnect(1, 0, 2)

	jitterRange(t, r.nextBackoff(), 1*time.Second)
	jitterRange(t, r.nextBackoff(), 2*time.Second, 2*time.Second) // 第二次起被 maxInterval 封顶，抖动后也不许超过
	jitterRange(t, r.nextBackoff(), 2*time.Second, 2*time.Second)
}

func TestReconnectNextBackoffSaturatesForLongRetrySeries(t *testing.T) {
	r := NewReconnect(1, 0, 2)

	// 第一次是起始间隔（1s），从第二次起才被 maxInterval 封顶。
	r.nextBackoff()
	for i := 0; i < 200; i++ {
		if got := r.nextBackoff(); got > 2*time.Second {
			t.Fatalf("jittered backoff %v exceeded maxInterval 2s", got)
		} else {
			jitterRange(t, got, 2*time.Second, 2*time.Second)
		}
	}
}

// TestReconnectBackoffJitters 钉住「有抖动」本身：如果哪天有人把 jitterBackoff
// 的随机项去掉，退避会退回确定性序列，发版重启时所有设备又要同秒撞门。
func TestReconnectBackoffJitters(t *testing.T) {
	const samples = 200

	min, max := time.Duration(1<<62), time.Duration(0)
	for i := 0; i < samples; i++ {
		got := jitterBackoff(10 * time.Second)
		jitterRange(t, got, 10*time.Second)
		if got < min {
			min = got
		}
		if got > max {
			max = got
		}
	}
	if max-min < 100*time.Millisecond {
		t.Fatalf("backoff jitter looks constant: min=%v max=%v over %d samples", min, max, samples)
	}
}

func TestJitterBackoffKeepsNonPositiveIntervals(t *testing.T) {
	if got := jitterBackoff(0); got != 0 {
		t.Fatalf("zero interval should stay zero, got %v", got)
	}
	if got := jitterBackoff(-time.Second); got != -time.Second {
		t.Fatalf("negative interval should be untouched, got %v", got)
	}
}
