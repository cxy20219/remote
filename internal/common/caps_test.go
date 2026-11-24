package common

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCaps(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: nil},
		{name: "blank", raw: "   ", want: nil},
		{name: "single", raw: "obs", want: []string{"obs"}},
		{name: "sorted and deduplicated", raw: "obs,aad,obs", want: []string{"aad", "obs"}},
		{name: "whitespace tolerated", raw: " obs , aad ", want: []string{"aad", "obs"}},
		{name: "unknown names are kept", raw: "future_thing", want: []string{"future_thing"}},
		{name: "illegal characters dropped", raw: "obs,<script>,aad", want: []string{"aad", "obs"}},
		{name: "uppercase dropped", raw: "OBS", want: nil},
		{name: "too long dropped", raw: strings.Repeat("a", MaxCapLen+1), want: nil},
		{name: "empty items dropped", raw: ",,obs,", want: []string{"obs"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ParseCaps(testCase.raw); !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("ParseCaps(%q) = %v, want %v", testCase.raw, got, testCase.want)
			}
		})
	}

	// 数量上限：超出部分丢弃，不报错。
	many := make([]string, 0, MaxCaps+5)
	for index := 0; index < MaxCaps+5; index++ {
		many = append(many, "cap"+string(rune('a'+index)))
	}
	if got := ParseCaps(strings.Join(many, ",")); len(got) > MaxCaps {
		t.Fatalf("ParseCaps kept %d caps, want at most %d", len(got), MaxCaps)
	}
}

func TestFormatCaps(t *testing.T) {
	cases := []struct {
		caps []string
		want string
	}{
		{caps: nil, want: ""},
		{caps: []string{}, want: ""},
		{caps: []string{"obs"}, want: "obs"},
		{caps: []string{"obs", "aad"}, want: "aad,obs"},
		{caps: []string{"obs", "obs"}, want: "obs"},
		{caps: []string{"obs", "BAD", "<x>"}, want: "obs"},
	}
	for _, testCase := range cases {
		if got := FormatCaps(testCase.caps); got != testCase.want {
			t.Fatalf("FormatCaps(%v) = %q, want %q", testCase.caps, got, testCase.want)
		}
	}

	// 往返：FormatCaps 的输出必须能被 ParseCaps 原样读回。
	formatted := FormatCaps([]string{"obs", "aad"})
	if got := ParseCaps(formatted); !reflect.DeepEqual(got, []string{"aad", "obs"}) {
		t.Fatalf("round trip = %v", got)
	}
}
