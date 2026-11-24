package server

import "testing"

// startServerAsync 在 goroutine 里跑真实 Start()，并把它的返回值原样收回。
//
// 不要让用例写成 `go func() { _ = srv.Start() }()`：Start 一失败就永远不会去拿
// data/.lock、也不会开始监听，而调用方等的是「锁被持住」或「/health 返回 200」，
// 于是启动失败退化成 10 秒超时，真实原因（状态读不出来、fd 用尽、bind 失败）
// 全被吞掉。等待循环里配 requireServerRunning 用。
//
// channel 带缓冲：Stop 之后 Start 正常返回（ErrServerClosed → nil）也不会漏 goroutine。
func startServerAsync(srv *Server) <-chan error {
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start() }()
	return startErr
}

// requireServerRunning 在等待循环的每一轮调用：Start 已经返回就先打出那个错误，
// 别等到超时才报「没拿到锁」这种被藏起来的原因。
func requireServerRunning(t *testing.T, startErr <-chan error) {
	t.Helper()
	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("the server returned from Start() before it was ready (it was stopped early)")
		}
		t.Fatalf("the server failed to start: %v", err)
	default:
	}
}
