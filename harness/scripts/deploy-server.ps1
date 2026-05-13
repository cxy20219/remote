# GoRemote Server Deployment Script for Linux
# Usage: .\deploy-server.ps1 -ServerIp "1.2.3.4" -SshUser "root" -SshPassword "xxx"

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIp,

    [Parameter(Mandatory=$true)]
    [string]$SshUser = "root",

    [Parameter(Mandatory=$true)]
    [string]$SshPassword,

    [string]$SshPort = "22",

    [string]$RemoteDir = "/opt/goremote",

    [string]$ConfigFile = ""
)

$ErrorActionPreference = "Stop"

$LocalBinary = "release/server-linux-amd64"
$RemoteBinary = "$RemoteDir/server"

if (-not (Test-Path $LocalBinary)) {
    Write-Error "Binary not found at $LocalBinary`nBuild with: `$env:GOOS=`"linux`"; `$env:GOARCH=`"amd64`"; go build -o release/server-linux-amd64 ./cmd/server/"
    exit 1
}

Write-Host "Deploying GoRemote Server to $ServerIp..."

$plinkArgs = "-batch", "-pw", $SshPassword, "-P", $SshPort

function Remote-Command {
    param([string]$Cmd)
    $output = & plink.exe @plinkArgs "$SshUser@$ServerIp" $Cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Remote command failed (non-zero exit): $output"
    }
    return $output
}

function Remote-Command-AllowFail {
    param([string]$Cmd)
    $output = & plink.exe @plinkArgs "$SshUser@$ServerIp" $Cmd 2>&1
    return $output
}

Write-Host "Creating remote directory..."
Remote-Command "mkdir -p $RemoteDir"

Write-Host "Stopping existing server..."
# Use AllowFail variant for stop commands — they exit non-zero when nothing to kill
Remote-Command-AllowFail "fuser -k 8080/tcp 2>/dev/null; pkill -9 -f 'server --config' 2>/dev/null; echo OK"

Write-Host "Uploading binary..."
$LocalBinaryFull = (Resolve-Path $LocalBinary).Path
& pscp.exe -P $SshPort -pw $SshPassword $LocalBinaryFull "$SshUser@$ServerIp`:$RemoteBinary" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to upload binary" }

Write-Host "Setting permissions..."
Remote-Command "chmod +x $RemoteBinary"

if ($ConfigFile -and (Test-Path $ConfigFile)) {
    Write-Host "Uploading config..."
    $RemoteConfig = "$RemoteDir/server.yaml"
    & pscp.exe -P $SshPort -pw $SshPassword $ConfigFile "$SshUser@$ServerIp`:$RemoteConfig" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to upload config" }
}

Write-Host "Starting server..."
$startCmd = "cd $RemoteDir && nohup ./server --config $RemoteDir/server.yaml </dev/null > $RemoteDir/server.log 2>&1 &"
# nohup & may cause plink to hang; use AllowFail variant with pipeline to unblock
$null = & plink.exe @plinkArgs "$SshUser@$ServerIp" $startCmd 2>&1 | Out-Null

Start-Sleep -Seconds 3

Write-Host "Checking health..."
$health = Remote-Command "curl -s http://localhost:8080/health 2>/dev/null || echo 'FAILED'"
if ($health -match "ok|status") {
    Write-Host "Server deployed successfully!" -ForegroundColor Green
} else {
    Write-Warning "Health check may have failed. Check logs at $RemoteDir/server.log"
    Write-Host "Last 10 lines of log:"
    Remote-Command "tail -10 $RemoteDir/server.log"
}

Write-Host "`nDeployment Summary:"
Write-Host "  Server IP: $ServerIp"
Write-Host "  Remote Dir: $RemoteDir"
Write-Host "  Binary: $RemoteBinary"
Write-Host "  Config: $RemoteDir/server.yaml"
Write-Host "  Log: $RemoteDir/server.log"
Write-Host "  Health: https://$ServerIp`:8080/health"