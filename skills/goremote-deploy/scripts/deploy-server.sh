#!/bin/bash
# GoRemote Server Deploy Script
# Usage: ./deploy-server.sh <server_ip> <ssh_password> [config_path]

set -e

SERVER_IP="${1:?Usage: $0 <server_ip> <ssh_password> [config_path]}"
SSH_PASS="${2:?Usage: $0 <server_ip> <ssh_password> [config_path]}"
CONFIG_PATH="${3:-assets/server-deploy.yaml.template}"
BINARY_PATH="../../bin/server"
REMOTE_DIR="/opt/goremote"
SERVER_PORT="${SERVER_PORT:-8080}"

echo "=== GoRemote Server Deploy ==="
echo "Server: ${SERVER_IP}"
echo "Target dir: ${REMOTE_DIR}"

# 1. Check binary
if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found at $BINARY_PATH"
    echo "Build with: GOOS=linux GOARCH=amd64 go build -o bin/server ./cmd/server"
    exit 1
fi

echo "Binary: OK ($(file "$BINARY_PATH" | cut -d: -f2))"

# 2. Prepare config
if [ ! -f "$CONFIG_PATH" ]; then
    echo "WARN: Config not found at $CONFIG_PATH, using defaults"
fi

# 3. Deploy
echo "Deploying..."

# Create remote directory
plink -batch -pw "$SSH_PASS" -P 22 "root@${SERVER_IP}" "mkdir -p ${REMOTE_DIR}"

# Upload binary
pscp -P 22 -pw "$SSH_PASS" "$BINARY_PATH" "root@${SERVER_IP}:${REMOTE_DIR}/server"

# Upload config
if [ -f "$CONFIG_PATH" ]; then
    pscp -P 22 -pw "$SSH_PASS" "$CONFIG_PATH" "root@${SERVER_IP}:${REMOTE_DIR}/config.yaml"
fi

# 4. Start service
plink -batch -pw "$SSH_PASS" -P 22 "root@${SERVER_IP}" "
    cd ${REMOTE_DIR}
    chmod +x server
    killall server 2>/dev/null || true
    sleep 1
    nohup ./server --config config.yaml > server.log 2>&1 &
    sleep 2
"

# 5. Verify
echo "Verifying..."
sleep 3
plink -batch -pw "$SSH_PASS" -P 22 "root@${SERVER_IP}" "
    curl -k -s https://localhost:${SERVER_PORT}/health || curl -s http://localhost:${SERVER_PORT}/health
"

echo ""
echo "=== Deploy Complete ==="
echo "Server: https://${SERVER_IP}:${SERVER_PORT}"
echo "Health:  curl -k https://${SERVER_IP}:${SERVER_PORT}/health"
