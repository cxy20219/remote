package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"goremote/internal/buildinfo"
)

func deviceDirty(store *StateStore) bool {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.dirty
}

// TestRecordAgentBuildWritesOnlyOnChange 钉住「只在变化时写」：版本是每次重连
// 都会带上来的元数据，每次都写会让 state 每 3 秒全量落盘一次。
func TestRecordAgentBuildWritesOnlyOnChange(t *testing.T) {
	srv := newObserveTestServer(t)
	srv.stateStore.AddDevice(&DeviceState{ID: "dev-1", Name: "dev-1", Status: deviceStatusAuthorized})
	if err := srv.stateStore.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if deviceDirty(srv.stateStore) {
		t.Fatal("the store must be clean after Save")
	}

	client := &Client{ClientID: "dev-1", agentVersion: "v2.7.0", agentCommit: "abc123"}
	srv.recordAgentBuild(client)
	device := srv.stateStore.GetDeviceByID("dev-1")
	if device.AgentVersion != "v2.7.0" || device.AgentCommit != "abc123" {
		t.Fatalf("device = %+v, want the reported build", device)
	}
	if !deviceDirty(srv.stateStore) {
		t.Fatal("a changed version must mark the store dirty")
	}

	// 重连同版本：不置 dirty。
	if err := srv.stateStore.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	srv.recordAgentBuild(client)
	if deviceDirty(srv.stateStore) {
		t.Fatal("reconnecting with the same version must not mark the store dirty")
	}

	// 老 agent（完全没带握手参数）：什么也不改，也不置 dirty。
	srv.recordAgentBuild(&Client{ClientID: "dev-1"})
	device = srv.stateStore.GetDeviceByID("dev-1")
	if device.AgentVersion != "v2.7.0" {
		t.Fatalf("agent_version = %q, an old agent must not clear it", device.AgentVersion)
	}
	if deviceDirty(srv.stateStore) {
		t.Fatal("an old agent reporting nothing must not mark the store dirty")
	}

	// 本地 dev 构建：有 commit、没有发布版本号（ver 只在注入版本时才发）。
	// 这一格最容易被漏掉——它会走到写入分支，必须只更新 commit，不能把
	// 已经记下的发布版本冲成空。
	srv.recordAgentBuild(&Client{ClientID: "dev-1", agentCommit: "fff000000000"})
	device = srv.stateStore.GetDeviceByID("dev-1")
	if device.AgentVersion != "v2.7.0" {
		t.Fatalf("agent_version = %q, a commit-only report must not clear it", device.AgentVersion)
	}
	if device.AgentCommit != "fff000000000" {
		t.Fatalf("agent_commit = %q, want the commit-only report", device.AgentCommit)
	}
	if err := srv.stateStore.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// 升级后重连：覆盖成新版本。
	srv.recordAgentBuild(&Client{ClientID: "dev-1", agentVersion: "v2.8.0", agentCommit: "def456"})
	device = srv.stateStore.GetDeviceByID("dev-1")
	if device.AgentVersion != "v2.8.0" || device.AgentCommit != "def456" {
		t.Fatalf("device = %+v, want the upgraded build", device)
	}

	// 未知设备：什么也不做，不能 panic。
	srv.recordAgentBuild(&Client{ClientID: "missing", agentVersion: "v1.0.0"})
	srv.recordAgentBuild(nil)
}

func getDevices(t *testing.T, srv *Server) []map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	srv.handleAPIListDevices(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("devices returned %d", recorder.Code)
	}
	var payload struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode devices: %v (%s)", err, recorder.Body.String())
	}
	return payload.Devices
}

// TestDevicesAPIReturnsAgentVersion 覆盖面板契约：agent_version 字符串 +
// agent_outdated 布尔，由服务端算好，面板不接触服务端版本号。
func TestDevicesAPIReturnsAgentVersion(t *testing.T) {
	previous := buildinfo.Version
	buildinfo.Version = "v2.8.0"
	t.Cleanup(func() { buildinfo.Version = previous })

	srv := newObserveTestServer(t)
	for _, device := range []*DeviceState{
		{ID: "outdated", Name: "outdated", Status: deviceStatusAuthorized, AgentVersion: "v2.7.0"},
		{ID: "current", Name: "current", Status: deviceStatusAuthorized, AgentVersion: "v2.8.0"},
		{ID: "newer", Name: "newer", Status: deviceStatusAuthorized, AgentVersion: "v2.9.0"},
		{ID: "unknown", Name: "unknown", Status: deviceStatusAuthorized},
	} {
		srv.stateStore.AddDevice(device)
	}

	byID := make(map[string]map[string]any)
	for _, entry := range getDevices(t, srv) {
		byID[entry["id"].(string)] = entry
	}

	cases := []struct {
		id           string
		wantVersion  string
		wantOutdated bool
	}{
		{id: "outdated", wantVersion: "v2.7.0", wantOutdated: true},
		{id: "current", wantVersion: "v2.8.0", wantOutdated: false},
		{id: "newer", wantVersion: "v2.9.0", wantOutdated: false},
		{id: "unknown", wantVersion: "", wantOutdated: false},
	}
	for _, testCase := range cases {
		entry, ok := byID[testCase.id]
		if !ok {
			t.Fatalf("device %s missing from the response", testCase.id)
		}
		// 字段必须始终存在（面板靠它判断「未知」而不是「没这个字段」）。
		version, present := entry["agent_version"]
		if !present {
			t.Fatalf("device %s has no agent_version field", testCase.id)
		}
		if version != testCase.wantVersion {
			t.Fatalf("device %s agent_version = %v, want %q", testCase.id, version, testCase.wantVersion)
		}
		outdated, present := entry["agent_outdated"]
		if !present {
			t.Fatalf("device %s has no agent_outdated field", testCase.id)
		}
		if outdated != testCase.wantOutdated {
			t.Fatalf("device %s agent_outdated = %v, want %t", testCase.id, outdated, testCase.wantOutdated)
		}
	}
}
