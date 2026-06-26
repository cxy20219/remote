package agent

import "testing"

func TestAgentProxyTargetValidation(t *testing.T) {
	if err := validateProxyTarget("example.com", 443); err != nil {
		t.Fatalf("validateProxyTarget valid domain: %v", err)
	}

	tests := []struct {
		host string
		port int
	}{
		{host: "", port: 443},
		{host: "bad name", port: 443},
		{host: "localhost", port: 443},
		{host: "127.0.0.1", port: 443},
		{host: "169.254.169.254", port: 80},
		{host: "example.com", port: 0},
		{host: "example.com", port: 65536},
	}

	for _, tc := range tests {
		if err := validateProxyTarget(tc.host, tc.port); err == nil {
			t.Fatalf("validateProxyTarget(%q, %d) succeeded, want error", tc.host, tc.port)
		}
	}
}
