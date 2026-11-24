package server

import "testing"

func TestAgentVersionOutdated(t *testing.T) {
	cases := []struct {
		name   string
		agent  string
		server string
		want   bool
	}{
		{name: "older agent", agent: "v2.7.0", server: "v2.8.0", want: true},
		{name: "older patch", agent: "v2.8.0", server: "v2.8.1", want: true},
		{name: "older minor", agent: "v2.7.9", server: "v2.8.0", want: true},
		{name: "older major", agent: "v1.99.99", server: "v2.0.0", want: true},
		{name: "equal", agent: "v2.8.0", server: "v2.8.0", want: false},
		{name: "no leading v on agent", agent: "2.8.0", server: "v2.8.0", want: false},
		{name: "agent newer", agent: "v2.9.0", server: "v2.8.0", want: false},
		{name: "agent dev", agent: "dev", server: "v2.8.0", want: false},
		{name: "server dev", agent: "v2.0.0", server: "dev", want: false},
		{name: "agent unknown", agent: "unknown", server: "v2.8.0", want: false},
		{name: "agent empty (old agent)", agent: "", server: "v2.8.0", want: false},
		{name: "prerelease ignored", agent: "v2.8.0-rc1", server: "v2.8.0", want: false},
		{name: "build suffix ignored", agent: "v2.7.0+dirty", server: "v2.8.0", want: true},
		{name: "both unparseable", agent: "abc", server: "xyz", want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := agentVersionOutdated(testCase.agent, testCase.server); got != testCase.want {
				t.Fatalf("agentVersionOutdated(%q, %q) = %t, want %t", testCase.agent, testCase.server, got, testCase.want)
			}
		})
	}
}

func TestCleanReportedVersion(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"   ":                       "",
		"v2.8.0":                    "v2.8.0",
		"v2.8.0; rm -rf /":          "v2.8.0rm-rf",
		"\x00\x01":                  "",
		"<script>alert(1)</script>": "scriptalert1script",
	}
	for raw, want := range cases {
		if got := cleanReportedVersion(raw); got != want {
			t.Fatalf("cleanReportedVersion(%q) = %q, want %q", raw, got, want)
		}
	}
}
