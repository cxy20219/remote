#requires -Version 5.1
[CmdletBinding()]
param(
    [int]    $Port         = 18080,
    [string] $WorkDir,
    [int]    $HeartbeatN   = 3,
    [int]    $HeartbeatSec = 5
)

<#
.SYNOPSIS
    Cross-language interop test: Go server + Rust agent.

.DESCRIPTION
    Spins up a freshly built Go server on 127.0.0.1:18080 and points the
    pre-built Rust agent at it. The script drives:

      1. register_new        - the Rust agent sends a zero-config `register`
                              message; the Go server lists the device under
                              /api/devices/pending.
      2. approve             - login as admin (password parsed from the
                              server's stdout) and approve via the HTTP API.
      3. enc_key decryption  - the Go server pushes `register_ok` with an
                              ECDH-protected enc_key. The Rust agent uses
                              its X25519 private key to derive the shared
                              secret, decrypts the key, and persists it.
                              The script reads the identity file and checks
                              the 64-hex-char `enc_key` field.
      4. (optional) tunnel round-trip - currently best-effort because the
                              Go server's `pendingLoop` only migrates an
                              authorized device into its in-memory `clients`
                              map on the next incoming `ping` frame. The
                              Rust agent's heartbeat is in place; the
                              round-trip succeeds once a few heartbeats
                              have fired after approval.

    Pre-conditions:
      * `cargo build --release` has produced
            target/release/tunnel-rs-server.exe
            target/release/tunnel-rs-agent.exe
      * `go run ./cmd/server` is buildable from `go-remote/` (Go 1.22+).
      * curl.exe and PowerShell 5.1 are on PATH (curl.exe is the default
        on Windows 10+).

    The script leaves no temp files behind outside of $WorkDir. The Go
    server and Rust agent are spawned in -NoNewWindow mode; their combined
    output is captured to $WorkDir/go-server.log and $WorkDir/rust-agent.log
    for debugging.

.EXAMPLE
    powershell -File bin/test-rust-agent-against-go-server.ps1
#>

$ErrorActionPreference = 'Stop'

# ---------- paths ----------
$RepoRoot  = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path          # E:\AI-work\go-remote
$GoRemote  = Join-Path $RepoRoot 'go-remote'                                # Go implementation
$RustRoot  = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path              # rust-remote/
if ($WorkDir) {
    $WorkDir = (Resolve-Path $WorkDir).Path
} else {
    $WorkDir = Join-Path $env:TEMP ("tunnel-rs-interop-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
}
$null = New-Item -ItemType Directory -Force -Path $WorkDir
$GoLog     = Join-Path $WorkDir 'go-server.log'
$AgentLog  = Join-Path $WorkDir 'rust-agent.log'
$StateFile = Join-Path $WorkDir 'server-state.json'  # <data>/server-state.json
$IdDir     = Join-Path $WorkDir 'agent-id'

Write-Host "[interop] work dir : $WorkDir"
Write-Host "[interop] go log   : $GoLog"
Write-Host "[interop] agent log: $AgentLog"

# ---------- helpers ----------
function Wait-Port {
    param([string]$Target, [int]$TimeoutSec = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $port = [int]($Target.Split(':')[-1])
    while ((Get-Date) -lt $deadline) {
        $ok = Test-NetConnection -ComputerName '127.0.0.1' -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($ok) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Get-AdminPassword {
    # slog JSON: {"time":"...","level":"INFO","msg":"Admin password (first run only)","password":"xxxxx"}
    # The `cmd /c` wrapper holds a write handle on the log; open with
    # FileShare.ReadWrite so we can read while go is still running.
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        $log_text = ""
        if (Test-Path -LiteralPath $GoLog) {
            $fs = $null
            try {
                $fs = [System.IO.File]::Open($GoLog, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
                $log_text = $reader.ReadToEnd()
            } catch {
                $log_text = ""
            } finally {
                if ($fs) { $fs.Close() }
            }
        }
        $m = [regex]::Match($log_text, '"msg":"Admin password[^"]*"\s*,\s*"password":"([^"]+)"')
        if ($m.Success) { return $m.Groups[1].Value }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "---- go-server.log dump ----"
    if (Test-Path -LiteralPath $GoLog) { Get-Content -LiteralPath $GoLog -Tail 30 }
    throw "admin password line not found in $GoLog (within 20s)"
}

# ---------- 1) start the Go server ----------
Write-Host "[interop] starting go server on 127.0.0.1:$Port"
# Kill any lingering listener on the target port from a previous run.
$listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
foreach ($c in $listener) {
    try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction Stop } catch { }
}
$goArgs = @('-host', '127.0.0.1',
            '-port', "$Port",
            '-data', $WorkDir,
            '-port-start', '30000',
            '-port-end', '30010',
            '-swagger', 'false')
$allGoArgs = @('run', './cmd/server') + $goArgs
# PowerShell 5.1 refuses to point RedirectStandardOutput and
# RedirectStandardError at the same file, so we wrap the go command in
# `cmd /c ... > log 2>&1` to merge both streams before redirecting.
$goExe = (Get-Command go.exe -ErrorAction SilentlyContinue).Source
if (-not $goExe) { throw "go.exe not found on PATH" }
$quotedArgs = ($allGoArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
$goProc = Start-Process -FilePath $goExe `
    -ArgumentList $allGoArgs `
    -WorkingDirectory $GoRemote `
    -RedirectStandardOutput $GoLog `
    -RedirectStandardError "NUL" `
    -NoNewWindow -PassThru

try {
    if (-not (Wait-Port -Target "127.0.0.1:$Port" -TimeoutSec 15)) {
        throw "go server did not open 127.0.0.1:$Port in time"
    }
    $password = Get-AdminPassword
    Write-Host "[interop] admin password: $password"

    # ---------- 2) login as admin ----------
    $body = '{"password":"' + $password + '"}'
    $tmpBody = Join-Path $WorkDir 'login.json'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($tmpBody, $body, $utf8)
    $loginOut = & curl.exe -sS -i -c (Join-Path $WorkDir 'cookie.txt') `
        -H 'Content-Type: application/json' `
        --data-binary "@$tmpBody" `
        "http://127.0.0.1:$Port/api/login"
    if ($LASTEXITCODE -ne 0) { throw "login curl failed" }
    # `-match` on a multi-line string in PS 5.1 only inspects the first line,
    # so we anchor on `(?m)` to look at the whole output.
    if (-not [regex]::IsMatch($loginOut, '(?m)^HTTP/1\.1 200')) {
        throw "login did not return 200:`n$loginOut"
    }
    Write-Host "[interop] login ok"

    # ---------- 3) start the Rust agent ----------
    $agentBin = Join-Path $RustRoot 'target\release\tunnel-rs-agent.exe'
    if (-not (Test-Path $agentBin)) {
        throw "rust agent binary not found: $agentBin (run cargo build --release first)"
    }
    $null = New-Item -ItemType Directory -Force -Path $IdDir
    $agentArgs = @("127.0.0.1:$Port", '--identity-dir', $IdDir)
    $agentProc = Start-Process -FilePath $agentBin `
        -ArgumentList $agentArgs `
        -RedirectStandardOutput $AgentLog `
        -RedirectStandardError "NUL" `
        -NoNewWindow -PassThru

    try {
        # ---------- 4) wait for the device to appear in /pending ----------
        $deviceId = $null
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline -and -not $deviceId) {
            $pending = & curl.exe -sS -b (Join-Path $WorkDir 'cookie.txt') "http://127.0.0.1:$Port/api/devices/pending" 2>$null
            if ($LASTEXITCODE -eq 0 -and $pending -match '"id"\s*:\s*"([^"]+)"') {
                $deviceId = $Matches[1]
            } else {
                Start-Sleep -Milliseconds 500
            }
        }
        if (-not $deviceId) {
            Write-Host "---- go server log (tail 50) ----"
            Get-Content $GoLog -Tail 50
            Write-Host "---- rust agent log (tail 50) ----"
            Get-Content $AgentLog -Tail 50
            throw "device did not show up in /api/devices/pending"
        }
        Write-Host "[interop] pending device: $deviceId"

        # ---------- 5) approve ----------
        $approveOut = & curl.exe -sS -i -X POST -b (Join-Path $WorkDir 'cookie.txt') `
            "http://127.0.0.1:$Port/api/devices/pending/$deviceId/approve"
        if (-not [regex]::IsMatch($approveOut, '(?m)^HTTP/1\.1 200')) {
            throw "approve did not return 200:`n$approveOut"
        }
        Write-Host "[interop] approved"

        # ---------- 6) wait for the agent to decrypt & persist enc_key ----------
        $deadline = (Get-Date).AddSeconds(15)
        $identityFile = Join-Path $IdDir 'identity.json'
        $ok = $false
        while ((Get-Date) -lt $deadline) {
            if (Test-Path $identityFile) {
                $content = ""
                $fs = $null
                try {
                    $fs = [System.IO.File]::Open($identityFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
                    $content = $reader.ReadToEnd()
                } catch {
                    $content = ""
                } finally {
                    if ($fs) { $fs.Close() }
                }
                if ($content -match '"enc_key"\s*:\s*"[0-9a-fA-F]{64}"') {
                    $ok = $true
                    break
                }
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $ok) {
            throw "agent did not persist enc_key (checked $identityFile)"
        }
        Write-Host "[interop] enc_key persisted (len=64)"

        # ---------- 7) (optional) tunnel round-trip ----------
        # The Go server's `pendingLoop` migrates the authorized device into
        # the in-memory `clients` map only on the next `ping` frame. The
        # Rust agent's heartbeat fires every --heartbeat-interval seconds
        # (default 30); the test only waits a few heartbeats.
        Write-Host "[interop] waiting $HeartbeatN heartbeats for the agent to be promoted client-side..."
        Start-Sleep -Seconds ($HeartbeatN * $HeartbeatSec + 2)

        $tBody = @"
{
  "client_id":     "$deviceId",
  "local_addr":    "127.0.0.1",
  "local_port":    22,
  "protocol":      "tcp",
  "exposure":      "public"
}
"@
        $tBodyPath = Join-Path $WorkDir 'tunnel.json'
        [System.IO.File]::WriteAllText($tBodyPath, $tBody, $utf8)
        $tOut = & curl.exe -sS -X POST -b (Join-Path $WorkDir 'cookie.txt') `
            -H 'Content-Type: application/json' `
            --data-binary "@$tBodyPath" `
            "http://127.0.0.1:$Port/api/tunnels"
        Write-Host "[interop] tunnel create response: $tOut"

        Write-Host "[interop] PASS (register / approve / enc_key)"
    } finally {
        if ($agentProc -and -not $agentProc.HasExited) {
            Stop-Process -Id $agentProc.Id -Force -ErrorAction SilentlyContinue
        }
    }
} finally {
    if ($goProc -and -not $goProc.HasExited) {
        Stop-Process -Id $goProc.Id -Force -ErrorAction SilentlyContinue
    }
}
