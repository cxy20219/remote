package backup

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// StateKeyEnvName 是 systemd EnvironmentFile 里的变量名，也是归档里
// meta/state.env 的格式锚点。
const StateKeyEnvName = "GOREMOTE_STATE_KEY"

// readStateEnvFile 读一份密钥文件，返回解析出的密钥和原始字节。
//
// 原始字节要一起返回：--include-key 会把文件原样放进归档，恢复时原样写回，
// 这样带注释或顺序的环境文件不会在往返中丢信息。
func readStateEnvFile(path string) (key string, raw []byte, err error) {
	raw, err = readSecretFile(path)
	if err != nil {
		return "", nil, err
	}
	key, err = parseStateEnv(string(raw))
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, raw, nil
}

// readKeyFileStrict 读「只放密钥本身」的文件（--key-file）。
func readKeyFileStrict(path string) (string, error) {
	raw, err := readSecretFile(path)
	if err != nil {
		return "", err
	}
	return parseStateEnv(string(raw))
}

// readSecretFile 只接受 0600 的普通文件，symlink 一律拒绝。
//
// 这条规则和 --state-key-file 完全一致，理由是同一个：配置文件被替换成
// symlink、或被同组用户读到，都是密钥泄漏，而且事后无从发现。Windows 没有
// POSIX 权限位，跳过权限检查（该保证只在 POSIX 上成立）。
func readSecretFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; point at the real key file", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%s has mode %04o; it must not be accessible by group or others (use 0600)", path, perm)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return data, nil
}

// parseStateEnv 解析密钥文件，两种写法都接受：
//
//   - systemd EnvironmentFile：GOREMOTE_STATE_KEY=base64:...（生产用的就是这种）；
//   - 只有一个密钥值的文件：整份内容就是密钥。
//
// 只按第一个 '=' 切分，因为 base64 密钥自带 '=' 填充。
func parseStateEnv(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "", errors.New("state key file is empty")
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != StateKeyEnvName {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if value == "" {
			return "", fmt.Errorf("%s is empty", StateKeyEnvName)
		}
		return value, nil
	}
	// 没有 NAME=value 行：整份文件就是密钥。多行内容几乎肯定是配置写错了，
	// 与其猜哪一行是密钥，不如直接报错。
	if strings.Contains(trimmed, "\n") {
		return "", fmt.Errorf("no %s= line found and the file holds more than one line", StateKeyEnvName)
	}
	return trimmed, nil
}
