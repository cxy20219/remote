package server

import "testing"

func TestAdvertisedTunnelHost(t *testing.T) {
	tests := []struct {
		name     string
		settings ServerSettings
		config   *Config
		reqHost  string
		want     string
	}{
		{
			name:     "public host wins",
			settings: ServerSettings{PublicHost: "server.example.com"},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "127.0.0.1:8080",
			want:     "server.example.com",
		},
		{
			name:     "request host strips port",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "api.example.com:8080",
			want:     "api.example.com",
		},
		{
			name:     "request host supports ipv6",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "[2001:db8::1]:8080",
			want:     "2001:db8::1",
		},
		{
			name:     "fallback to configured host",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "10.0.0.5"}},
			reqHost:  "",
			want:     "10.0.0.5",
		},
		{
			name:     "fallback to loopback",
			settings: ServerSettings{},
			config:   &Config{Server: ServerConfig{Host: "0.0.0.0"}},
			reqHost:  "",
			want:     "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{
				config:     tc.config,
				stateStore: NewStateStoreWithSettings(tc.settings),
			}
			got := srv.advertisedTunnelHost(tc.reqHost)
			if got != tc.want {
				t.Fatalf("advertisedTunnelHost(%q) = %q, want %q", tc.reqHost, got, tc.want)
			}
		})
	}
}

func TestTunnelPublicAddr(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "hostname", host: "server.example.com", port: 15001, want: "server.example.com:15001"},
		{name: "ipv4", host: "127.0.0.1", port: 15001, want: "127.0.0.1:15001"},
		{name: "ipv6", host: "2001:db8::1", port: 15001, want: "[2001:db8::1]:15001"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelPublicAddr(tc.host, tc.port)
			if got != tc.want {
				t.Fatalf("tunnelPublicAddr(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}

func TestNormalizeTunnelTarget(t *testing.T) {
	tests := []struct {
		name      string
		localAddr string
		localPort int
		protocol  string
		wantAddr  string
		wantProto string
		wantErr   bool
	}{
		{name: "default addr and protocol", localPort: 22, wantAddr: "127.0.0.1", wantProto: "tcp"},
		{name: "trim and lowercase protocol", localAddr: " localhost ", localPort: 8080, protocol: "TCP", wantAddr: "localhost", wantProto: "tcp"},
		{name: "reject udp", localAddr: "127.0.0.1", localPort: 53, protocol: "udp", wantErr: true},
		{name: "reject port zero", localAddr: "127.0.0.1", localPort: 0, protocol: "tcp", wantErr: true},
		{name: "reject port above range", localAddr: "127.0.0.1", localPort: 70000, protocol: "tcp", wantErr: true},
		{name: "reject addr with embedded port", localAddr: "127.0.0.1:22", localPort: 22, protocol: "tcp", wantErr: true},
		{name: "allow ipv6 host", localAddr: "::1", localPort: 22, protocol: "tcp", wantAddr: "::1", wantProto: "tcp"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, proto, err := normalizeTunnelTarget(tc.localAddr, tc.localPort, tc.protocol, "127.0.0.1")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr != tc.wantAddr || proto != tc.wantProto {
				t.Fatalf("got addr/proto %q/%q, want %q/%q", addr, proto, tc.wantAddr, tc.wantProto)
			}
		})
	}
}
