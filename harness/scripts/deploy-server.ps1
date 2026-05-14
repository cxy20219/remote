# GoRemote Server Zero-Config Deployment Script for Linux
# Usage: .\deploy-server.ps1 -ServerIp "1.2.3.4" -SshUser "root" -SshPassword "xxx"
# 关联流程: ../workflow/zero-config-deploy-verify.md
# 依赖: plink.exe, pscp.exe (PuTTY 工具链)

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIp,

    [Parameter(Mandatory=$true)]
    [string]$SshUser = "root",

    [Parameter(Mandatory=$true)]
    [string]$SshPassword,

    [string]$SshPort = "22",

    [string]$RemoteDir = "/root/goremote",

    [string]$LocalBinary = "harness/assets/bin/server-linux-amd64",

    [int]$ServerPort = 8080
)

$ErrorActionPreference = "Stop"
$RemoteBinary = "$RemoteDir/server"

if (-not (Test-Path $LocalBinary)) {
    Write-Error "Binary not found at $LocalBinary`nBuild with: `$env:GOOS=`"linux`"; `$env:GOARCH=`"amd64`"; go build -o $LocalBinary ./cmd/server/"
    exit 1
}

Write-Host "=== Deploying GoRemote Server (Zero-Config) ===" -ForegroundColor Cyan
Write-Host "Target: $SshUser@$ServerIp`:$SshPort"

function Remote-Command { param([string]$Cmd) & plink.exe -batch -pw $SshPassword -P $SshPort "$SshUser@$ServerIp" $Cmd 2>&1 }
function Remote-Command-AllowFail { param([string]$Cmd) & plink.exe -batch -pw $SshPassword -P $SshPort "$SshUser@$ServerIp" $Cmd 2>&1 }

Write-Host "[1/5] Creating remote directory..."
Remote-Command "mkdir -p $RemoteDir/data" | Out-Null

Write-Host "[2/5] Stopping existing server..."
Remote-Command-AllowFail 'kill -9 $(pgrep -f "./server") 2>/dev/null; echo stopped' | Out-Null

Write-Host "[3/5] Uploading binary..."
$LocalBinaryFull = (Resolve-Path $LocalBinary).Path
& pscp.exe -P $SshPort -pw $SshPassword $LocalBinaryFull "$SshUser@$ServerIp`:$RemoteBinary" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to upload binary" }

Write-Host "[4/5] Starting server..."
Remote-Command "chmod +x $RemoteBinary" | Out-Null
$null = & plink.exe -batch -pw $SshPassword -P $SshPort "$SshUser@$ServerIp" "cd $RemoteDir && nohup ./server --data $RemoteDir/data > $RemoteDir/server.log 2>&1 &" 2>&1 | Out-Null

Start-Sleep -Seconds 2

Write-Host "[5/5] Verifying health..."
$health = Remote-Command "curl -s http://localhost:$ServerPort/health 2>/dev/null || echo FAILED"
if ($health -match '"ok"') {
    Write-Host "Health check passed!" -ForegroundColor Green
} else {
    Write-Warning "Health check may have failed. Check logs."
    Remote-Command "tail -5 $RemoteDir/server.log"
}

# Show admin password
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "Server: http://$ServerIp`:$ServerPort"
$pwd = Remote-Command "grep -o 'password\":\"[^\"]*\"' $RemoteDir/server.log | head -1 | cut -d'\"' -f4"
if ($pwd) {
    Write-Host "Admin password (first-run only): $pwd" -ForegroundColor Yellow
}
Write-Host "Log: $RemoteDir/server.log"
