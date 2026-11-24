package server

import (
	"sync"
	"time"
)

// 隧道流量历史：两级环形缓冲，纯内存态（重启归零，不落盘、不进 state schema）。
//
// 为什么是两级：1 小时窗口要 120 个点、24 小时窗口要 144 个点，采样粒度差 20 倍。
// 用一套桶要么丢分辨率、要么把内存翻 20 倍。两条环各存一份，每隧道
// (120+144) × 32B ≈ 8.25KB，4 条隧道约 33KB。
//
// 每条隧道一把自己的锁：采样协程写、HTTP 读，都不碰 tm.mu，建删隧道时的
// 落盘 fsync 不会挡住流量曲线的请求，反过来读曲线也不会挡数据转发。
const (
	trafficWindow1h  = "1h"
	trafficWindow24h = "24h"

	trafficShortInterval = 30 * time.Second  // 1h 窗口：30 秒一个桶
	trafficShortPoints   = 120               // 30s × 120 = 1h
	trafficLongInterval  = 600 * time.Second // 24h 窗口：10 分钟一个桶
	trafficLongPoints    = 144               // 10min × 144 = 24h
)

// trafficBucket 是一个时间桶。sum(rx/tx) 是桶内累计字节，count 是折进来的
// 1 秒采样次数：平均值 = 字节 / count。这样**未满的当前桶天然按已过秒数折算**，
// 不需要另外除以整个区间长度（除整段会把刚过去 3 秒的桶说成慢了 10 倍）。
type trafficBucket struct {
	epoch int64  // 对齐后的桶序号 = unixNano / interval；0 表示没写过
	rx    uint64 // 外部连接 → 目标，本桶累计字节
	tx    uint64 // 目标 → 外部，本桶累计字节
	count uint32 // 折进本桶的采样次数
}

// trafficRing 是固定长度的环形桶数组，按桶序号定位，写满后回绕覆盖最旧的桶。
type trafficRing struct {
	interval time.Duration
	buckets  []trafficBucket
	next     int   // 下一次写入的位置
	last     int64 // 最近一次写入的桶序号；0 表示还没写过
	mu       sync.Mutex
}

func newTrafficRing(interval time.Duration, points int) *trafficRing {
	return &trafficRing{
		interval: interval,
		buckets:  make([]trafficBucket, points),
	}
}

// record 把一个采样周期的字节数折进当前桶；跨桶时先推进桶序号，中间空着的
// 桶必须清零，否则回绕后上一轮的旧数据会被当成「刚过去那几桶」返回。
func (r *trafficRing) record(now time.Time, rx, tx uint64) {
	if r == nil {
		return
	}
	epoch := now.UnixNano() / int64(r.interval)

	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case r.last == 0:
		r.resetLocked(epoch)
	case epoch > r.last:
		gap := epoch - r.last
		if gap >= int64(len(r.buckets)) {
			// 整个窗口都过期了（例如服务被挂起很久）：从头再开一圈。
			r.resetLocked(epoch)
			break
		}
		for i := int64(0); i < gap; i++ {
			r.next = (r.next + 1) % len(r.buckets)
			r.buckets[r.next] = trafficBucket{epoch: r.last + 1 + i}
		}
		r.last = epoch
	case epoch < r.last:
		// 时钟回拨：扔掉这批采样，不能拿旧时间戳覆盖已经画出来的历史。
		return
	}

	bucket := &r.buckets[r.next]
	bucket.rx += rx
	bucket.tx += tx
	bucket.count++
}

// resetLocked 把整圈桶清空并从 epoch 重新开始，调用方持有 r.mu。
func (r *trafficRing) resetLocked(epoch int64) {
	for i := range r.buckets {
		r.buckets[i] = trafficBucket{}
	}
	r.next = 0
	r.last = epoch
	r.buckets[0] = trafficBucket{epoch: epoch}
}

// snapshot 返回固定长度、时间升序的平均速率序列（B/s），最后一个点是当前桶。
// now 只用来算「当前是哪个桶」，历史点都按桶序号对齐取。
func (r *trafficRing) snapshot(now time.Time, points int) (rx, tx []uint64) {
	rx = make([]uint64, points)
	tx = make([]uint64, points)
	if r == nil {
		return rx, tx
	}
	nowEpoch := now.UnixNano() / int64(r.interval)

	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < points; i++ {
		epoch := nowEpoch - int64(points-1-i)
		bucket := r.findLocked(epoch)
		if bucket == nil {
			continue // 没有采样过的区间就是 0，不是「未知」
		}
		rx[i] = bucket.rx / uint64(bucket.count)
		tx[i] = bucket.tx / uint64(bucket.count)
	}
	return rx, tx
}

// findLocked 按桶序号找桶；桶数最多 144，线性扫比维护索引更不容易错。
func (r *trafficRing) findLocked(epoch int64) *trafficBucket {
	for i := range r.buckets {
		if r.buckets[i].count == 0 || r.buckets[i].epoch != epoch {
			continue
		}
		return &r.buckets[i]
	}
	return nil
}

// trafficHistory 是一条隧道的两级历史。
type trafficHistory struct {
	short *trafficRing // 30s 桶 × 120 = 1h
	long  *trafficRing // 10min 桶 × 144 = 24h
}

func newTrafficHistory() *trafficHistory {
	return &trafficHistory{
		short: newTrafficRing(trafficShortInterval, trafficShortPoints),
		long:  newTrafficRing(trafficLongInterval, trafficLongPoints),
	}
}

// record 把同一批采样折进两条环。
func (h *trafficHistory) record(now time.Time, rx, tx uint64) {
	if h == nil {
		return
	}
	h.short.record(now, rx, tx)
	h.long.record(now, rx, tx)
}

// TunnelTrafficResponse 是 /api/tunnels/:id/traffic 的响应：两条等长的速率序列
// （B/s，整数），按时间升序，最后一个是当前区间。窗口决定 interval_seconds 与
// points，长度永远等于 points——前端可以直接按固定宽度画图。
type TunnelTrafficResponse struct {
	Window          string   `json:"window"`
	IntervalSeconds int      `json:"interval_seconds"`
	Points          int      `json:"points"`
	RX              []uint64 `json:"rx"`
	TX              []uint64 `json:"tx"`
}

// TunnelTraffic 按窗口取一条隧道的流量历史；未知窗口返回 false。
// 隧道存在但还没采过样（刚创建、刚重启）时返回全 0 序列，不是错误。
func (t Tunnel) TunnelTraffic(window string, now time.Time) (TunnelTrafficResponse, bool) {
	var ring *trafficRing
	var response TunnelTrafficResponse

	switch window {
	case trafficWindow1h:
		response = TunnelTrafficResponse{
			Window:          trafficWindow1h,
			IntervalSeconds: int(trafficShortInterval / time.Second),
			Points:          trafficShortPoints,
		}
		if t.stats != nil && t.stats.history != nil {
			ring = t.stats.history.short
		}
	case trafficWindow24h:
		response = TunnelTrafficResponse{
			Window:          trafficWindow24h,
			IntervalSeconds: int(trafficLongInterval / time.Second),
			Points:          trafficLongPoints,
		}
		if t.stats != nil && t.stats.history != nil {
			ring = t.stats.history.long
		}
	default:
		return TunnelTrafficResponse{}, false
	}

	response.RX, response.TX = ring.snapshot(now, response.Points)
	return response, true
}
