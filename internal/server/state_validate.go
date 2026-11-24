package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// StateSnapshot 是一次离线状态文件校验的结果：备份恢复在真正替换目录之前，
// 就是靠它回答「这个文件能不能被当前二进制启动、里面有多少设备与隧道」。
type StateSnapshot struct {
	SchemaVersion     int
	Encrypted         bool
	Devices           int
	AuthorizedDevices int
	Tunnels           int
	Ports             []int
	AdminPasswordSet  bool
}

// SupportedStateSchemaVersion 暴露当前二进制能读的最高状态 schema 版本，
// 供备份包在解包阶段就给出「文件比这个二进制新」的明确错误。
func SupportedStateSchemaVersion() int {
	return stateSchemaVersion
}

// ValidateStateFile 用真实的 StateStore 加载状态文件，完整走一遍启动路径：
// 版本检查 → 解密 → 迁移 → 反序列化。
//
// 校验在临时目录的副本上跑，因为 Load 在需要迁移或补写时会把文件重写一遍。
// 让校验直接碰待恢复的文件，就等于把「校验」变成「修改」：manifest 里的
// sha256 立刻失效，--dry-run 也不再是只读操作。
//
// 失败一律返回 error，绝不 panic——调用方是 CLI，要的是非零退出码与一句话。
func ValidateStateFile(path, stateKey string) (StateSnapshot, error) {
	var snapshot StateSnapshot

	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	if len(data) == 0 {
		return snapshot, fmt.Errorf("%s is empty", path)
	}

	// 先读明文头：schema 与「是否加密」必须在解密之前就可见，否则没密钥时
	// 连「这份状态是加密的」都说不出来。
	var header struct {
		SchemaVersion int             `json:"schema_version"`
		Encrypted     json.RawMessage `json:"encrypted"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return snapshot, fmt.Errorf("parse %s: %w", path, err)
	}
	snapshot.SchemaVersion = header.SchemaVersion
	snapshot.Encrypted = len(header.Encrypted) > 0 && string(header.Encrypted) != "null"

	dir, err := os.MkdirTemp("", "goremote-validate-")
	if err != nil {
		return snapshot, err
	}
	defer os.RemoveAll(dir)

	copyPath := filepath.Join(dir, "server-state.json")
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		return snapshot, err
	}

	store := NewStateStore(copyPath)
	if err := store.SetEncryptionKey(stateKey); err != nil {
		return snapshot, err
	}
	if err := store.Load(); err != nil {
		return snapshot, err
	}

	devices := store.GetAllDevices()
	snapshot.Devices = len(devices)
	snapshot.AuthorizedDevices = store.CountDevicesByStatus(deviceStatusAuthorized)
	snapshot.AdminPasswordSet = store.AdminPasswordInitialized()

	portSet := make(map[int]struct{})
	for _, tunnel := range store.GetTunnels() {
		snapshot.Tunnels++
		if tunnel.PublicPort > 0 {
			portSet[tunnel.PublicPort] = struct{}{}
		}
	}
	snapshot.Ports = make([]int, 0, len(portSet))
	for port := range portSet {
		snapshot.Ports = append(snapshot.Ports, port)
	}
	sort.Ints(snapshot.Ports)

	return snapshot, nil
}
