package netplane

import (
	"strings"
	"testing"
)

func TestBuildACLSplitsRolesAndSorts(t *testing.T) {
	snapshot := Snapshot{
		Hub: Hub{Interface: "wg-grm"},
		Peers: []Peer{
			{DeviceID: "b", PublicKey: "key-b", Address: "10.77.0.9", Role: "client", Enabled: true},
			{DeviceID: "a", PublicKey: "key-a", Address: "10.77.0.2", Role: "client", Enabled: true},
			{DeviceID: "e", PublicKey: "key-e", Address: "10.77.0.3", Role: "endpoint", Enabled: true},
			{DeviceID: "off", PublicKey: "key-off", Address: "10.77.0.4", Role: "client", Enabled: false},
		},
	}
	acl := buildACL(snapshot)
	if acl.Interface != "wg-grm" {
		t.Fatalf("interface = %q", acl.Interface)
	}
	if got := strings.Join(acl.Clients, ","); got != "10.77.0.2/32,10.77.0.9/32" {
		t.Fatalf("clients = %q (disabled peers must be excluded, addresses sorted)", got)
	}
	if got := strings.Join(acl.Endpoints, ","); got != "10.77.0.3/32" {
		t.Fatalf("endpoints = %q", got)
	}
}

func TestACLSignatureTracksRoles(t *testing.T) {
	client := ACL{Interface: "wg-grm", Clients: []string{"10.77.0.2/32"}}
	endpoint := ACL{Interface: "wg-grm", Endpoints: []string{"10.77.0.2/32"}}
	if client.signature() == endpoint.signature() {
		t.Fatal("moving a peer between roles must change the ACL signature")
	}
	again := ACL{Interface: "wg-grm", Clients: []string{"10.77.0.2/32"}}
	if client.signature() != again.signature() {
		t.Fatal("the same ACL must produce the same signature")
	}
}

func aclSection(t *testing.T, table, start, end string) string {
	t.Helper()
	from := strings.Index(table, start)
	if from < 0 {
		t.Fatalf("missing %q in:\n%s", start, table)
	}
	rest := table[from+len(start):]
	to := strings.Index(rest, end)
	if to < 0 {
		t.Fatalf("missing %q after %q in:\n%s", end, start, table)
	}
	return rest[:to]
}

func TestBuildACLTableScopesDropsToWG(t *testing.T) {
	table := buildACLTable(ACL{
		Interface: "wg-grm",
		Clients:   []string{"10.77.0.2/32"},
		Endpoints: []string{"10.77.0.3/32"},
	})

	for _, want := range []string{
		"add table inet goremote",
		"delete table inet goremote",
		"table inet goremote {",
		`iifname "wg-grm" jump wg_fwd`,
		`oifname "wg-grm" jump wg_fwd_rev`,
		"ct state established,related accept",
		"meta l4proto { tcp, udp } ip saddr @clients ip daddr @endpoints counter accept",
		"icmp type echo-request ip saddr @clients ip daddr @endpoints accept",
		"elements = { 10.77.0.2/32 }",
		"elements = { 10.77.0.3/32 }",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("ruleset missing %q:\n%s", want, table)
		}
	}

	// forward base chain 只能有两条带接口限定的 jump：任何无条件规则（尤其是
	// drop）都会切断 Docker DNAT / 容器出站 / 所有本机转发。
	forward := aclSection(t, table, "chain forward {", "chain wg_fwd {")
	if strings.Contains(forward, "counter drop") || strings.Contains(forward, " drop") {
		t.Fatalf("the forward base chain must not drop unconditionally:\n%s", forward)
	}
	if !strings.Contains(forward, `iifname "wg-grm"`) || !strings.Contains(forward, `oifname "wg-grm"`) {
		t.Fatalf("both jumps must be interface-scoped:\n%s", forward)
	}
	if !strings.Contains(forward, "policy accept") {
		t.Fatalf("the forward base chain must keep policy accept:\n%s", forward)
	}

	// 反向链只放 established/related：任何 allow 规则都会给「非 wg 源伪造
	// saddr=10.77.0.x」开口子（v3-P1-1 的原始洞）。
	reverse := aclSection(t, table, "chain wg_fwd_rev {", "chain input {")
	if !strings.Contains(reverse, "ct state established,related accept") {
		t.Fatalf("the reverse chain must accept established traffic:\n%s", reverse)
	}
	if !strings.Contains(reverse, "counter drop") {
		t.Fatalf("the reverse chain must drop everything else:\n%s", reverse)
	}
	for _, forbidden := range []string{"@clients", "@endpoints", "tcp", "udp", "icmp"} {
		if strings.Contains(reverse, forbidden) {
			t.Fatalf("the reverse chain must not contain %q (forged-source hole):\n%s", forbidden, reverse)
		}
	}

	// 三条链尾 drop 只出现在 wg_fwd / wg_fwd_rev / wg_in 里。
	if got := strings.Count(table, "counter drop"); got != 3 {
		t.Fatalf("expected exactly 3 scoped drops, got %d:\n%s", got, table)
	}
	if got := strings.Count(table, "policy accept"); got != 2 {
		t.Fatalf("expected policy accept on the two base chains, got %d:\n%s", got, table)
	}
}

func TestBuildACLTableWithoutElements(t *testing.T) {
	table := buildACLTable(ACL{Interface: "wg-grm"})
	if strings.Contains(table, "elements =") {
		t.Fatalf("empty sets must omit the elements line:\n%s", table)
	}
	if !strings.Contains(table, "set clients {") || !strings.Contains(table, "set endpoints {") {
		t.Fatalf("both role sets must exist:\n%s", table)
	}
}
