package server

import "testing"

func TestAdvertisedTunnelHost(t *testing.T) {
	tests := []struct {
		name    string
		server  *Server
		reqHost string
		want    string
	}{
		{
			name: "public host wins",
			server: &Server{config: &Config{
				Server: ServerConfig{Host: "0.0.0.0"},
				Tunnel: TunnelConfig{PublicHost: "server.example.com"},
			}},
			reqHost: "127.0.0.1:8080",
			want:    "server.example.com",
		},
		{
			name: "request host strips port",
			server: &Server{config: &Config{
				Server: ServerConfig{Host: "0.0.0.0"},
			}},
			reqHost: "api.example.com:8080",
			want:    "api.example.com",
		},
		{
			name: "request host supports ipv6",
			server: &Server{config: &Config{
				Server: ServerConfig{Host: "0.0.0.0"},
			}},
			reqHost: "[2001:db8::1]:8080",
			want:    "2001:db8::1",
		},
		{
			name: "fallback to configured host",
			server: &Server{config: &Config{
				Server: ServerConfig{Host: "10.0.0.5"},
			}},
			reqHost: "",
			want:    "10.0.0.5",
		},
		{
			name: "fallback to loopback",
			server: &Server{config: &Config{
				Server: ServerConfig{Host: "0.0.0.0"},
			}},
			reqHost: "",
			want:    "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.server.advertisedTunnelHost(tc.reqHost)
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
