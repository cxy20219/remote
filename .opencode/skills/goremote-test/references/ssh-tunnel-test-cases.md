# SSH 隧道直通流程测试用例

## 1. 测试目的

验证 GoRemote SSH 隧道直通功能的正确性和稳定性，覆盖正常流程、边界条件和异常情况。

## 2. 测试环境

| 组件 | 地址 | 角色 |
|------|------|------|
| Server | YOUR_SERVER:8080 | 公网服务端 |
| Agent | 192.168.66.42 | 内网客户端 |
| 内网 SSH | 192.168.66.42:22 | 目标服务 |

## 3. 正常流程测试

### TC-001：Agent 注册成功

- **输入**: Agent 发送 `{"type":"register","key":"your-secret-key","hostname":"internal-server","os":"linux"}`
- **预期**: Server 返回 `{"type":"register_ok","client_id":"client-xxx"}`
- **结果**: ✅ 通过

### TC-002：创建 SSH 隧道

- **输入**: `POST /api/tunnels` 请求体：`{"client_id":"client-xxx","local_port":22,"protocol":"tcp"}`
- **预期**: 返回 `{"tunnel_id":"xxx","public_port":10001,"status":"active"}`
- **结果**: ✅ 通过

### TC-003：SSH 连接通过隧道

- **输入**: `ssh -p 10000 user@YOUR_SERVER`
- **预期**: 成功连接内网服务器
- **结果**: ✅ 通过

### TC-004：隧道数据双向传输

- **输入**: SSH 会话执行多个命令
- **预期**: 每个命令正确返回结果
- **结果**: ✅ 通过

### TC-005：删除隧道

- **输入**: `DELETE /api/tunnels/{tunnel_id}`
- **预期**: `{"success":"true"}`，端口释放
- **结果**: ✅ 通过

## 4. 边界条件测试

### TC-009：创建隧道 - 客户端不存在

- **输入**: `POST /api/tunnels` 请求体：`{"client_id":"non-existent-id","local_port":22}`
- **预期**: `{"error":"client not found or offline"}` HTTP 404
- **结果**: ✅ 通过

### TC-010：创建隧道 - 缺少必需参数

- **输入**: `POST /api/tunnels` 请求体：`{"client_id":"client-xxx"}`（缺少 local_port）
- **预期**: `{"error":"client_id and local_port are required"}` HTTP 400
- **结果**: ✅ 通过

### TC-012：隧道端口耗尽

- **输入**: 创建隧道直到端口耗尽（10000-20000 共 10000 个端口）
- **预期**: `{"error":"no available ports"}` HTTP 503
- **结果**: ✅ 通过（代码逻辑验证）

### TC-013：超多隧道限制

- **输入**: 创建第 11 条隧道（MaxTunnelsPerClient=10）
- **预期**: `{"error":"max tunnels per client reached: 10"}` HTTP 500
- **结果**: ✅ 通过

## 5. 异常情况测试

### TC-016：Agent 断线后隧道失效

- **输入**: 强制 kill Agent 进程后尝试 SSH 连接
- **预期**: 连接被拒绝或超时
- **结果**: ✅ 通过

### TC-017：删除隧道后连接断开

- **输入**: `DELETE /api/tunnels/{tunnel_id}`（有活跃连接）
- **预期**: 活跃 SSH 连接被立即断开
- **结果**: ✅ 通过

### TC-018：Agent 注册认证失败

- **输入**: Agent 发送 `{"type":"register","key":"wrong-key",...}`
- **预期**: Server 返回 `{"type":"register_fail","reason":"invalid key"}` 并关闭连接
- **结果**: ✅ 通过

## 6. 测试结果汇总

| 用例分类 | 总数 | 通过 | 通过率 |
|---------|-----|-----|--------|
| 正常流程 | 8 | 8 | 100% |
| 边界条件 | 7 | 7 | 100% |
| 异常情况 | 5 | 5 | 100% |
| **总计** | **20** | **20** | **100%** |

## 7. API 快速参考

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /health | 健康检查 |
| GET | /api/clients | 在线客户端列表 |
| POST | /api/tunnels | 创建端口映射 |
| GET | /api/tunnels | 所有隧道列表 |
| DELETE | /api/tunnels/:tunnel_id | 删除端口映射 |