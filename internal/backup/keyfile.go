package backup

import (
	"fmt"
	"os"
	"runtime"

	"goremote/internal/common"
)

// readStateEnvFile 读一份密钥文件，返回解析出的密钥和原始字节。
//
// 原始字节要一起返回：--include-key 会把文件原样放进归档，恢复时原样写回，
// 这样带注释或顺序的环境文件不会在往返中丢信息。
func readStateEnvFile(path string) (key string, raw []byte, err error) {
	raw, err = readSecretFile(path)
	if err != nil {
		return "", nil, err
	}
	key, err = common.ParseStateKeyEnv(string(raw))
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, raw, nil
}

// readKeyFileStrict 读 --key-file；解析规则与 --state-key-file 完全一致，
// 所以 backup --include-key 导出的 state.env 可以直接拿来启动服务。
func readKeyFileStrict(path string) (string, error) {
	raw, err := readSecretFile(path)
	if err != nil {
		return "", err
	}
	key, err := common.ParseStateKeyEnv(string(raw))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
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
