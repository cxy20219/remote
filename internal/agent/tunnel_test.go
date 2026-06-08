package agent

import "testing"

func TestLocalServiceAddr(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "ipv4", host: "127.0.0.1", port: 22, want: "127.0.0.1:22"},
		{name: "hostname", host: "example.com", port: 8080, want: "example.com:8080"},
		{name: "ipv6", host: "::1", port: 443, want: "[::1]:443"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := localServiceAddr(tc.host, tc.port)
			if got != tc.want {
				t.Fatalf("localServiceAddr(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}
