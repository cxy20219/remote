#!/bin/bash
# GoRemote Agent Zero-Config Deploy Script
# Usage: ./deploy-agent.sh <agent_ip> <ssh_user> <ssh_password> <server_address>
# 关联流程: ../workflow/zero-config-deploy-verify.md
# 依赖: plink (PuTTY), pscp
# 输入: build/agent-linux-amd64
# 输出: 远端 /opt/goremote/agent + /opt/goremote/agent.log
#
# 零配置架构：Agent 只需服务器地址，无需任何配置文件。

set -e

AGENT_IP="${1:?Usage: $0 <agent_ip> <ssh_user> <ssh_password> <server_address>}"
SSH_USER="${2:?}"
SSH_PASS="${3:?}"
SERVER_ADDR="${4:?}"
BINARY_PATH="build/agent-linux-amd64"
REMOTE_DIR="/opt/goremote"

echo "=== GoRemote Agent Zero-Config Deploy ==="
echo "Target: ${SSH_USER}@${AGENT_IP}"
echo "Server: ${SERVER_ADDR}"

if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found at $BINARY_PATH"
    echo "Build: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o $BINARY_PATH ./cmd/agent"
    exit 1
fi

echo "[1/3] Uploading binary..."
plink -batch -pw "$SSH_PASS" -P 22 "${SSH_USER}@${AGENT_IP}" "mkdir -p ${REMOTE_DIR}" 2>/dev/null || true
pscp -P 22 -pw "$SSH_PASS" "$BINARY_PATH" "${SSH_USER}@${AGENT_IP}:${REMOTE_DIR}/agent"

echo "[2/3] Starting agent..."
plink -batch -pw "$SSH_PASS" -P 22 "${SSH_USER}@${AGENT_IP}" "
    cd ${REMOTE_DIR}
    chmod +x agent
    killall agent 2>/dev/null || true
    sleep 1
    nohup ./agent --server ${SERVER_ADDR} > agent.log 2>&1 &
    sleep 2
"

echo "[3/3] Done."
echo "Agent will appear as pending in the server's Web UI."
echo "Approve at: http://${SERVER_ADDR}/"
echo "Agent log: ${REMOTE_DIR}/agent.log"
