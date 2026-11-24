package buildinfo

import "testing"

func TestSanitize(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain version", raw: "v2.8.0", want: "v2.8.0"},
		{name: "commit with dirty", raw: "055ab4d5a1b2+dirty", want: "055ab4d5a1b2+dirty"},
		{name: "prerelease", raw: "v2.8.0-rc1", want: "v2.8.0-rc1"},
		{name: "whitespace trimmed", raw: "  v2.8.0\n", want: "v2.8.0"},
		{name: "illegal chars stripped", raw: "v2.8.0;rm -rf /", want: "v2.8.0rm-rf"},
		{name: "control chars stripped", raw: "v2\x00.8\x1b.0", want: "v2.8.0"},
		{name: "chinese stripped", raw: "版本2.8", want: "2.8"},
		{name: "empty", raw: "", want: Unknown},
		{name: "only illegal", raw: "\x00\x01 <script>", want: "script"},
		{name: "only separators", raw: " \t\n", want: Unknown},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := Sanitize(testCase.raw); got != testCase.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", testCase.raw, got, testCase.want)
			}
		})
	}

	// 长度上限：200 字符的输入必须被截断到 MaxVersionLen，且不带任何垃圾字符。
	long := ""
	for index := 0; index < 200; index++ {
		long += "a"
	}
	if got := Sanitize(long); len(got) != MaxVersionLen {
		t.Fatalf("Sanitize(200 chars) length = %d, want %d", len(got), MaxVersionLen)
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		raw  string
		want [3]int
		ok   bool
	}{
		{raw: "v2.8.0", want: [3]int{2, 8, 0}, ok: true},
		{raw: "2.8.0", want: [3]int{2, 8, 0}, ok: true},
		{raw: "v2.8.0-rc1", want: [3]int{2, 8, 0}, ok: true},
		{raw: "v2.8.0+dirty", want: [3]int{2, 8, 0}, ok: true},
		{raw: "v10.20.30", want: [3]int{10, 20, 30}, ok: true},
		{raw: "  v2.8.0  ", want: [3]int{2, 8, 0}, ok: true},
		{raw: "dev", ok: false},
		{raw: "unknown", ok: false},
		{raw: "", ok: false},
		{raw: "v2.8", ok: false},
		{raw: "v2.8.0.1", ok: false},
		{raw: "v2.8.x", ok: false},
		{raw: "v2.8.0abc", ok: false},
		{raw: "v-2.8.0", ok: false},
		{raw: "v2..0", ok: false},
	}
	for _, testCase := range cases {
		got, ok := Parse(testCase.raw)
		if ok != testCase.ok {
			t.Fatalf("Parse(%q) ok = %t, want %t", testCase.raw, ok, testCase.ok)
		}
		if ok && got != testCase.want {
			t.Fatalf("Parse(%q) = %v, want %v", testCase.raw, got, testCase.want)
		}
	}
}

func TestStringAndCommit(t *testing.T) {
	previous := Version
	t.Cleanup(func() { Version = previous })

	Version = ""
	if got := String(); got != "dev" {
		t.Fatalf("String() without injection = %q, want dev", got)
	}

	Version = "v2.8.0"
	if got := String(); got != "v2.8.0" {
		t.Fatalf("String() = %q, want v2.8.0", got)
	}

	// 注入值同样要清洗：ldflags 也可能被打错。
	Version = "v2.8.0 dirty;"
	if got := String(); got != "v2.8.0dirty" {
		t.Fatalf("String() with dirty chars = %q", got)
	}

	Version = ""
	commit := Commit()
	if commit == "" {
		t.Fatal("Commit() must never return an empty string")
	}
	// 有 VCS 信息时是 12 位 hex（可能带 +dirty），测试二进制里通常如此；
	// 从源码目录外构建时回落 dev。
	if commit != "dev" && len(commit) != 12 && len(commit) != len("0123456789ab+dirty") {
		t.Fatalf("Commit() = %q, want dev, 12 hex chars, or 12 hex chars + \"+dirty\"", commit)
	}
}
