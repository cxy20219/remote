#!/bin/bash
# GoRemote Agent Deploy Script
# Usage: ./deploy-agent.sh <agent_ip> <ssh_user> <ssh_password> <server_address> [config_path]
#
# 注意：此脚本在 Windows 上使用 plink/pscp，需要确保已安装 PuTTY

set -e

AGENT_IP="${1:?Usage: $0 <agent_ip> <ssh_user> <ssh_password> <server_address> [config_path]}"
SSH_USER="${2:?}"
SSH_PASS="${3:?}"
SERVER_ADDR="${4:?}"
CONFIG_PATH="${5:-../assets/agent.yaml.template}"
BINARY_PATH="../../bin/agent"
REMOTE_DIR="/opt/goremote"

echo "=== GoRemote Agent Deploy ==="
echo "Agent: ${SSH_USER}@${AGENT_IP}"
echo "Server: ${SERVER_ADDR}"

# 1. Check binary
if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found at $BINARY_PATH"
    echo "Build with: GOOS=linux GOARCH=amd64 go build -o bin/agent ./cmd/agent"
    exit 1
fi

# 2. Deploy
echo "Deploying..."

# Create remote directory (if writable)
plink -batch -pw "$SSH_PASS" -P 22 "${SSH_USER}@${AGENT_IP}" "mkdir -p ${REMOTE_DIR}" || true

# Upload binary
pscp -P 22 -pw "$SSH_PASS" "$BINARY_PATH" "${SSH_USER}@${AGENT_IP}:${REMOTE_DIR}/agent"

# 3. Prepare and upload config
if [ -f "$CONFIG_PATH" ]; then
    sed -e "s/{{SERVER_ADDRESS}}/${SERVER_ADDR}/g" \
        -e "s/{{AUTH_KEY}}/test-secret-key/g" \
        -e "s/{{AGENT_HOSTNAME}}/internal-server/g" \
        -e "s/{{AGENT_OS}}/linux/g" \
        "$CONFIG_PATH" > /tmp/agent-deploy.yaml

    pscp -P 22 -pw "$SSH_PASS" /tmp/agent-deploy.yaml "${SSH_USER}@${AGENT_IP}:${REMOTE_DIR}/config.yaml"
fi

# 4. Start agent
echo "Starting agent..."
plink -batch -pw "$SSH_PASS" -P 22 "${SSH_USER}@${AGENT_IP}" "
    cd ${REMOTE_DIR}
    chmod +x agent
    killall agent 2>/dev/null || true
    sleep 1
    nohup ./agent --config config.yaml > agent.log 2>&1 &
    sleep 2
"

echo ""
echo "=== Agent Deploy Complete ==="
echo "Check registration: curl -k https://${SERVER_ADDR}/api/clients"