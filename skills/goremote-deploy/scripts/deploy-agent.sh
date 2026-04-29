#!/bin/bash
# GoRemote Agent Deploy Script
# Usage: ./deploy-agent.sh <agent_ip> <ssh_user> <ssh_password> <server_address> [config_path]

set -e

AGENT_IP="${1:?Usage: $0 <agent_ip> <ssh_user> <ssh_password> <server_address> [config_path]}"
SSH_USER="${2:?}"
SSH_PASS="${3:?}"
SERVER_ADDR="${4:?}"
CONFIG_PATH="${5:-assets/agent.yaml.template}"
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

# 2. Prepare config
if [ ! -f "$CONFIG_PATH" ]; then
    cat > /tmp/agent-deploy.yaml <<EOF
server:
  address: "${SERVER_ADDR}"

auth:
  key: "test-secret-key"

reconnect:
  interval: 5
  max_interval: 60

log:
  level: "info"
EOF
    CONFIG_PATH="/tmp/agent-deploy.yaml"
    echo "Using default config"
fi

# 3. Deploy
echo "Deploying..."
plink -batch -pw "$SSH_PASS" -P 22 "${SSH_USER}@${AGENT_IP}" "mkdir -p ${REMOTE_DIR}"
pscp -P 22 -pw "$SSH_PASS" "$BINARY_PATH" "${SSH_USER}@${AGENT_IP}:${REMOTE_DIR}/agent"
pscp -P 22 -pw "$SSH_PASS" "$CONFIG_PATH" "${SSH_USER}@${AGENT_IP}:${REMOTE_DIR}/agent.yaml"

# 4. Start agent
plink -batch -pw "$SSH_PASS" -P 22 "${SSH_USER}@${AGENT_IP}" "
    cd ${REMOTE_DIR}
    chmod +x agent
    killall agent 2>/dev/null || true
    sleep 1
    nohup ./agent --config agent.yaml > agent.log 2>&1 &
    sleep 2
    head -10 agent.log
"

echo ""
echo "=== Agent Deploy Complete ==="
echo "Check registration: curl https://${SERVER_ADDR}/api/clients"
