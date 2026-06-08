# PowerShell 5.1 跨语言脚本踩坑

> 适用：Windows + PowerShell 5.1（默认 `WindowsPowerShell\v1.0`）写跨语言 e2e 脚本（Go server + Rust agent）。
> 关联脚本：`rust-remote/bin/test-rust-agent-against-go-server.ps1`。

## 1. Unicode 标点破坏参数解析

**现象**：
```
PositionalParameterNotFound
```
即使脚本明显接受了命名参数 `-HeartbeatN 2 -HeartbeatSec 5`，PS 5.1 报"找不到实际参数 + 位置格式参数"。

**根因**：em-dash `—` (U+2014)、en-dash `–` (U+2013)、省略号 `…` (U+2026) 在 PS 5.1 默认 OEM/ANSI 代码页下不是合法标识符字符，破坏 token 化。脚本里这些字符只出现在 `<#...#>` 注释块中，理论上不该影响参数解析，但实际 PS 解析器在 `param()` 之后扫描整个脚本时会扫到这些字符。

**修法**：
- **写脚本时避免**：`—` → `--`、`–` → `-`、`…` → `...`。
- 调试时：`Format-Hex script.ps1 | Select-Object -First 10` 看前几行字节确认是纯 ASCII。

**反例**：用 `Set-Content -Value $c.Replace([char]0x2014, '-')` 改写脚本会失败（`[char]` 只接受单字符），且 `.Replace` 在 PS 5.1 默认 `String.Replace(oldChar, newChar)` 也是单字符，**必须用 `.Replace([string], [string])**。

## 2. Start-Process 不允许 stdout/stderr 指向同一文件

**现象**：
```
cannot process command because RedirectStandardOutput and
RedirectStandardError are set to the same file
```

**根因**：PS 5.1 `Start-Process` 不允许 `-RedirectStandardOutput X -RedirectStandardError X`（同一文件被两个 handle 打开会冲突）。

**修法**：三种选择：
1. **用 `cmd /c "command > log 2>&1"`** 包装 — 走 cmd 进程 shell 重定向，PS 不感知。
2. **分两个文件** — 调试时手工 cat 合并。
3. **PS 7+ 的 `5>&1` 或 process 重定向** — 不适用 PS 5.1。

**推荐**：方法 1，但要注意 `cmd /c "go run ..."` 中 `go` 必须用全路径 `(Get-Command go.exe).Source`，否则 `cmd` 找不到（在 PS PATH 与 cmd PATH 不同）。

## 3. `cmd` 包装进程持有文件句柄

**现象**：脚本用 `cmd /c "go run ... > $GoLog 2>&1"` 启动 Go server 后，`Get-Content $GoLog` 或 `[System.IO.File]::ReadAllText($GoLog)` 报"该文件正被另一个进程使用"。

**根因**：`cmd.exe` 是 `go run` 的父进程，继承 stdout 重定向，持有 `GoLog` 的写句柄。PS 默认 `Get-Content` / `File.ReadAllText` 用 `FileShare.Read`，不允许与 `FileShare.Write` 并存。

**修法**：用 `File.Open` + `FileShare.ReadWrite` 显式共享：
```powershell
$fs = [System.IO.File]::Open($GoLog, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
try {
    $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
    $log_text = $reader.ReadToEnd()
} finally { $fs.Close() }
```

**注意**：`Start-Process` 子进程退出后句柄释放，但脚本运行时 cmd 还活着。

## 4. `-notmatch` 多行字符串只检首行

**现象**：`$loginOut` 是多行（curl -i 返回 headers + body），`$loginOut -notmatch 'HTTP/1.1 200'` 仍为真（断言 200 OK），即使第一行就是 `HTTP/1.1 200 OK`。

**根因**：PS 5.1 `-match` 默认不启用 multiline 模式。

**修法**：用 `[regex]::IsMatch($text, '(?m)^HTTP/1\.1 200')` 显式开 multiline；或 split 后用 `-contains`。

## 5. 端口清理（前次运行残留）

**现象**：前次脚本异常退出后 Go server 没杀干净，端口 18080 仍被占。下次脚本 `Test-NetConnection` 在编译完成前就看到端口 listen（其实是僵尸），但 Go server 实际没启动。

**修法**：脚本入口先 `Get-NetTCPConnection` + `Stop-Process` 清掉僵尸：
```powershell
$listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
foreach ($c in $listener) {
    try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction Stop } catch { }
}
```

## 6. Wait-Port 成功后日志可能还没写

**现象**：`Test-NetConnection` 看到 18080 listen 时立刻读 `$GoLog`，但 slog 还没 flush（Go 用 `slog.Info` 默认 sync，但 `cmd` 包装下 stdout 缓冲可能延迟）。

**修法**：轮询读取直到正则匹配（带 20s deadline），不要只读一次：
```powershell
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    $log_text = ...  # shared read
    $m = [regex]::Match($log_text, '"msg":"Admin password[^"]*"\s*,\s*"password":"([^"]+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    Start-Sleep -Milliseconds 500
}
```

## 7. PowerShell 变量名大小写不敏感

**现象**：`$Heartbeats` 和 `$HeartbeatS`（或任何仅大小写差异）会被 PS 当作同一变量，后定义覆盖前定义。

**修法**：命名时保证差异≥2 字符（用 `$HeartbeatN` + `$HeartbeatSec` 而不是 `$HeartbeatS` + `$HeartbeatSec`）。

## 8. Go server CLI 实际 flag

**现象**：以为 Go server 接受 `-addr` / `-state`，报"flag provided but not defined"。

**实际 flag**（看 `internal/server/config.go`）：
- `-host` (默认 0.0.0.0)
- `-port` (默认 8080)
- `-tls-cert` / `-tls-key` (可选)
- `-data` (state dir，默认 ./data)
- `-tunnel` (默认 true)
- `-port-start` / `-port-end` (默认 10000/20000)
- `-max-tunnels` / `-local-addr` / `-public-host`
- `-swagger` (默认 true)
- `-log-level` / `-log-file` / `-log-max-size-mb` / `-log-max-backups`

**state file 路径**：`<data>/server-state.json`（不是 `-state`）。

## 9. Go server admin 密码格式

slog JSON 一行：
```json
{"time":"...","level":"INFO","msg":"Admin password (first run only)","password":"22ff6734-892"}
```
**两种 msg 都打印**："Generated admin credentials" 和 "Admin password (first run only)"，先打 Generated 再打 First run only。匹配 `"msg":"Admin password` 即可（不是 `Generated`），拿到的是"first run only" 那个 password。

## 10. 关联资源

- [Rust 端口编译 / clippy 踩坑](rust-remote-build-pitfalls.md) — Rust 端
- [跨语言 e2e 流程](../workflow/rust-remote-verify.md) — 端到端验证
- [PowerShell 远程命令转义经验](../../../go-remote/harness/experience/zero-config-testing-lessons.md) — 类似的转义/编码坑
- [PowerShell curl 中文编码经验](../../../go-remote/harness/experience/gitee-release-utf8.md) — `Invoke-WebRequest` UTF-16 坑
