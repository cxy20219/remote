# GoRemote Server Deploy Script (Windows PowerShell)
# 将服务端部署到远程 Linux 服务器
# Usage: .\deploy-server.ps1 -ServerIp "1.2.3.4" -SshPassword "xxx" [-ConfigPath "config.yaml"]

param(
    [Parameter(Mandatory=$true)] [string]$ServerIp,
    [Parameter(Mandatory=$true)] [string]$SshPassword,
    [string]$ConfigPath = "assets/server-deploy.yaml.template",
    [string]$PlinkPath = "C:\Program Files\PuTTY\plink.exe",
    [string]$PscpPath = "C:\Program Files\PuTTY\pscp.exe",
    [string]$BinaryPath = "../../bin/server",
    [string]$RemoteDir = "/opt/goremote"
)

Write-Host "=== GoRemote Server Deploy (Windows) ==="
Write-Host "Server: $ServerIp"

# Check binary
if (-not (Test-Path $BinaryPath)) {
    Write-Host "ERROR: Binary not found at $BinaryPath"
    Write-Host "Build: GOOS=linux GOARCH=amd64 go build -o bin/server ./cmd/server"
    exit 1
}

Write-Host "Binary: OK"

# Deploy
Write-Host "Deploying..."
& $PlinkPath -batch -pw $SshPassword -P 22 "root@$ServerIp" "mkdir -p $RemoteDir"
& $PscpPath -P 22 -pw $SshPassword $BinaryPath "root@${ServerIp}:${RemoteDir}/server"
if (Test-Path $ConfigPath) {
    & $PscpPath -P 22 -pw $SshPassword $ConfigPath "root@${ServerIp}:${RemoteDir}/config.yaml"
}

# Start
& $PlinkPath -batch -pw $SshPassword -P 22 "root@$ServerIp" @"
cd $RemoteDir
chmod +x server
killall server 2>/dev/null || true
sleep 1
nohup ./server --config config.yaml > server.log 2>&1 &
sleep 2
curl -k -s https://localhost:8080/health || curl -s http://localhost:8080/health
"@

Write-Host "=== Deploy Complete ==="
