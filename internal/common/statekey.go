package common

import (
	"errors"
	"fmt"
	"strings"
)

// StateKeyEnvName 是 systemd EnvironmentFile 里的变量名，也是 state.env 的格式锚点。
//
// --state-key-file、backup --state-env-file、restore --key-file / --install-key
// 全都走 ParseStateKeyEnv 这一份解析：否则「备份导出的密钥喂不进启动参数」
// 这种往返不一致会一直藏在部署路径里，直到真出事那天才暴露。
const StateKeyEnvName = "GOREMOTE_STATE_KEY"

// ParseStateKeyEnv 解析一份密钥文件内容，两种写法都接受：
//
//   - systemd EnvironmentFile：GOREMOTE_STATE_KEY=base64:...（生产用的就是这种）；
//   - 只有一个密钥值的文件：整份内容就是密钥。
//
// 只按第一个 '=' 切分，因为 base64 密钥自带 '=' 填充。
func ParseStateKeyEnv(content string) (string, error) {
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
