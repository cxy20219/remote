# Gitee Release 中文编码问题

## 现象

通过 PowerShell 的 `Invoke-RestMethod` 或 `curl.exe` 调用 Gitee API 创建/更新 Release 时，`body` 字段中的中文在保存后变成乱码。

```json
// 期望的 body
"端口占用检测"

// Gitee 实际保存的 body
"端口占用检�?*
```

## 根因

PowerShell 5.1 传递包含中文字符的字符串到 JSON 序列化或 curl 参数时，字符编码在命令管道中损坏。具体表现为：

- `Invoke-RestMethod` 的 `-Body` 参数使用系统默认编码（GBK/GB2312）而非 UTF-8
- `curl.exe` 的 `--data` 或 `--data-raw` 参数从 PowerShell 接收的已是损坏的 UTF-8 字节
- `.NET `[System.IO.File]::WriteAllText` 写入的文件虽然是 UTF-8 无 BOM，但 PowerShell 传递给调用时的中文字符串本身已损坏

## 解决方案

### 正确方案：用 Go 程序发送 API 请求（推荐）

Go 的 `json.Marshal` 正确编码 UTF-8，避免 PowerShell 的编码问题：

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type ReleaseReq struct {
	AccessToken    string `json:"access_token"`
	TagName        string `json:"tag_name"`
	Name           string `json:"name"`
	TargetCommitish string `json:"target_commitish"`
	Prerelease     bool   `json:"prerelease"`
	Body           string `json:"body"`
}

func main() {
	reqBody := ReleaseReq{
		AccessToken:     "your_token",
		TagName:         "v1.1.0",
		Name:            "v1.1.0",
		TargetCommitish: "master",
		Body:            "## v1.1.0 更新内容\n\n### 新功能\n\n**端口占用检测**\n- 创建隧道时自动跳过被系统占用的端口",
	}

	data, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://gitee.com/api/v5/repos/YOUR_USER/YOUR_REPO/releases", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println(string(respBody))
}
```

### 不可靠的方案（已验证失败）

1. **PowerShell `Invoke-RestMethod` + `-Body` 传字符串** — 中文损坏
2. **PowerShell 写 JSON 文件 + `curl.exe -d @file.json`** — 文件写操作时中文已损坏
3. **`[System.IO.File]::WriteAllText` 写入 UTF-8 文件** — 传入的中文字符串在 PowerShell 层面已损坏
4. **PATCH API 更新 release** — 即使 body 正确，Gitee PATCH 接口可能返回 400

## 验证方法

```powershell
# GET 验证中文是否正常保存
curl.exe -s "https://gitee.com/api/v5/repos/YOUR_USER/YOUR_REPO/releases/tags/v1.1.0?access_token=YOUR_TOKEN" | ConvertFrom-Json | Select-Object -ExpandProperty body
```

## 关联资源

- `harness/workflow/encrypted-tunnel-deploy-verify.md` — Release 打包与发布流程
