package server

import (
	"bytes"
	"net"
	"testing"
)

func TestProxyTargetValidationRejectsUnsafeTargets(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
	}{
		{name: "localhost", host: "localhost", port: 80},
		{name: "loopback", host: "127.0.0.1", port: 80},
		{name: "metadata", host: "169.254.169.254", port: 80},
		{name: "bad port", host: "example.com", port: 0},
		{name: "control char", host: "bad\nname", port: 80},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateProxyTarget(tc.host, tc.port); err == nil {
				t.Fatalf("validateProxyTarget(%q, %d) succeeded, want error", tc.host, tc.port)
			}
		})
	}
}

func TestProxyTargetValidationAllowsDomain(t *testing.T) {
	if err := validateProxyTarget("example.com", 443); err != nil {
		t.Fatalf("validateProxyTarget: %v", err)
	}
}

func TestSOCKS5HandshakeWithPasswordAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pm := NewProxyManager(nil)
	proxy := &Proxy{AuthEnabled: true, Username: "user", password: "pass"}

	result := make(chan struct {
		host string
		port int
		err  error
	}, 1)
	go func() {
		host, port, err := pm.socks5Handshake(proxy, server)
		result <- struct {
			host string
			port int
			err  error
		}{host: host, port: port, err: err}
	}()

	client.Write([]byte{0x05, 0x01, 0x02})
	method := make([]byte, 2)
	client.Read(method)
	if !bytes.Equal(method, []byte{0x05, 0x02}) {
		t.Fatalf("auth method = %v, want username/password", method)
	}

	client.Write([]byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'})
	auth := make([]byte, 2)
	client.Read(auth)
	if !bytes.Equal(auth, []byte{0x01, 0x00}) {
		t.Fatalf("auth response = %v, want success", auth)
	}

	client.Write([]byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb})
	got := <-result
	if got.err != nil {
		t.Fatalf("socks5Handshake: %v", got.err)
	}
	if got.host != "example.com" || got.port != 443 {
		t.Fatalf("target = %s:%d, want example.com:443", got.host, got.port)
	}
}

func TestCreateProxyWithManualPortReservesPortStatus(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen probe: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	tm := NewTunnelManager(nil, port, port)
	srv := &Server{tunnelManager: tm}
	pm := NewProxyManager(srv)
	srv.proxyManager = pm

	proxy, err := pm.CreateProxy("client-1", nil, port, TunnelExposureServerLocal, "", "")
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	if status := tm.GetPortStatus(); status.Allocated != 1 || status.AvailableCount != 0 {
		t.Fatalf("port status after create = allocated %d available %d, want 1/0", status.Allocated, status.AvailableCount)
	}

	if err := pm.CloseProxy(proxy.ProxyID); err != nil {
		t.Fatalf("CloseProxy: %v", err)
	}
	if status := tm.GetPortStatus(); status.Allocated != 0 || status.AvailableCount != 1 {
		t.Fatalf("port status after close = allocated %d available %d, want 0/1", status.Allocated, status.AvailableCount)
	}
}
