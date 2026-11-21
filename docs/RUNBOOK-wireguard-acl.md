# WireGuard 组网 ACL：部署与回滚

适用版本：阶段 1（`netplane` 接管 `wg-grm`，`table inet goremote` 生效）。
本文只讲 ACL 这一层的部署、验证和回滚；组网本身的绑定流程见面板。

## 0. 前置条件（缺一项就不要升级）

| 项 | 检查 | 说明 |
|---|---|---|
| `wireguard-tools` | `command -v wg` | 缺了 `Probe` 失败 → 接口 down、VPN 写接口 503（fail-closed） |
| `iproute2` | `command -v ip` | 同上 |
| `nftables` | `command -v nft && nft --version` | **本版把 nft 变成硬依赖**；缺了同样 fail-closed |
| 权限 | `systemctl show -p User goremote` / `AmbientCapabilities` | 需要 root 或 `CAP_NET_ADMIN`（建 link、装表、写 sysctl） |
| `state` 加密 | 启动日志无 `state encryption is required` | hub 私钥必须进加密区，否则拒绝启用 |
| 转发 | `sysctl net.ipv4.ip_forward` = 1 | 组网与既有隧道都依赖 |

`nft` 缺失、权限不足、表语法错误都走同一条路：**接口被 `ip link set wg-grm down`，VPN 写接口 503，面板与既有隧道不受影响**。

## 1. 升级二进制

```bash
systemctl stop goremote                 # 会断开 3 条既有隧道（NAS SSH / memos / Windows SSH）
install -m 0755 /usr/local/bin/goremote-server /usr/local/bin/goremote-server.bak   # 回滚用，必须先生成
install -m 0755 ./goremote-server /usr/local/bin/goremote-server
systemctl start goremote
```

首次启动（state 里已有 peer）时，netplane 会按 state 自动建表，不需要手工 `nft` 命令：

```bash
journalctl -u goremote -n 30 --no-pager | grep -Ei 'wireguard|nft|ACL'
# 正常：没有 "wireguard initial reconcile failed"
# 异常：wireguard ACL is not active; the interface is kept down (fail-closed)...
```

启动顺序是 `Probe → Ensure（建 link、配私钥/地址/redirects，**不 up**）→
nft 装表 → 下发 peer → 最后 ip link set up`。接口在装表与 peer 就位前始终是
DOWN 的，`iifname "wg-grm"` 不匹配任何包；因此冷启动、首次升级、以及表被
外部 flush 后的重建都不存在「peer 可达但 ACL 没就绪」的窗口。`ip link set up`
也是 UDP 监听端口冲突唯一会暴露的一步（`wg set listen-port` 的 rc 不可靠）。

## 2. 确认 ACL 生效

### 2.1 表结构

```bash
nft list table inet goremote
```

应看到：`set clients` / `set endpoints`（元素是各设备的 `/32`）、
`chain forward`（两条带 `iifname "wg-grm"` / `oifname "wg-grm"` 的 jump，`policy accept`）、
`chain wg_fwd`（`ct state established,related accept` → client→endpoint 的 tcp/udp counter accept）
`chain wg_fwd_rev`（只有 established + drop）、`chain input` + `chain wg_in`。
**base chain 上不能出现无条件的 `drop`**——那是切断 Docker DNAT / 容器出站 / 所有本机转发的写法。

### 2.2 接口状态

```bash
curl -s -b cookies.txt http://127.0.0.1:8080/api/vpn/status | jq '{acl_ready, acl_warning, infra_error, link_up, link_error, endpoint_warning, peers: [.peers[] | {device_id, wg_ip, handshake_age, rx_bytes, tx_bytes}]}'
```

`acl_ready` 只表示「nft 表已安装且与当前期望一致」；链路是否可用还要看
`infra_error` 为空（banner 判据是 `infra_error != "" || !acl_ready`）。
`link_up` 是每次请求现读的接口管理状态（`IFF_UP`），描述此刻；`acl_ready` /
`infra_error` 描述上一轮 reconcile。接口被外部 `ip link set down` 后 `link_up`
立即为 false，而另外两个字段最多要等 30s 自愈；`link_error` 是探测失败的原因。
若 `link_error` 报解析失败，先看服务器 iproute2 版本。
`rx_bytes/tx_bytes` 用来判断链路是否真的在走数据（只有 `handshake_age` 不够）。

### 2.3 行为验证（建议在维护窗口）

| 用例 | 预期 |
|---|---|
| client → 另一 client 的任意端口 | 超时；`nft list chain inet goremote wg_fwd` 的 drop 计数增长 |
| client → endpoint 的放行端口 | 通；`counter packets` 增长 |
| endpoint → client（新连接） | 超时（链尾 drop） |
| 从 hub 的 Docker/VPC 主动连 client | 超时；`wg_fwd_rev` 的 drop 计数增长 |
| client → `10.77.0.1:8080`（面板） | 超时 |
| 任意从 wg 进来的伪造源（saddr=其他 client） | 被 drop（WireGuard 的 /32 cryptokey routing 之前就丢） |
| 既有隧道 / Docker publish | 不受影响 |

计数器在**每次整表替换时清零**；peer/集合没变时不会重载表，读计数前先用 2.2 确认没有正在进行的变更。

## 3. 30 秒回滚到「无 ACL」状态

ACL 装错时优先恢复业务，再排查：

```bash
# 1) 先停服务：否则 30s 的自愈 ticker 会把刚删掉的表重新装回来
systemctl stop goremote
# 2) 删表（服务已停，不会被重装）
nft delete table inet goremote 2>/dev/null || true
# 3) 需要退回旧二进制时：
install -m 0755 /usr/local/bin/goremote-server.bak /usr/local/bin/goremote-server
systemctl start goremote
```

验证：`nft list tables | grep goremote` 为空；`/health` 正常；既有隧道恢复。
`systemctl stop` 会同时断开面板与隧道（同一个进程），这是预期；停服期间 VPN 也不可用——
本版**不提供**「接口 up 但无 ACL」的运行模式。

**回滚到旧二进制的风险必须知道**：旧版本没有 ACL（或没有 fail-closed），
它把接口拉起来之后 peer 之间、peer→VPC/元数据是全端口可达的。回滚到
`goremote-server.bak` 等于主动进入 fail-open 状态；只应在确认可以接受这段
暴露（或已同步收紧安全组）时使用，否则宁可停服排查。

**`ip link set wg-grm down` 不是持久切断**：30s 自愈 ticker 会在下一轮
`Ensure → 装表 → 下发 peer → up` 里把接口重新拉起来（≤30s）。要持久切断 VPN，
必须停服务（`systemctl stop goremote`）并 `nft delete table inet goremote`；
只想临时断几秒可以用 down，但要接受它会被自动恢复。

## 4. 排障速查

| 现象 | 先看 | 处理 |
|---|---|---|
| VPN 写接口 503，`infra_error` 含 `install wireguard nft table` | `nft --version`、`journalctl -u goremote` | 装 nftables / 补权限；修好后 `POST /api/vpn/reconcile` 手动触发 |
| `acl_ready=false` 但 `infra_error` 为空 | `nft list tables` | 表被外部 `flush` 了；下一次 reconcile 自动重装，或手动 reconcile |
| 握手成功但 SSH 不通 | `nft list chain inet goremote wg_fwd` 的 drop 计数 | 检查 client/endpoint 的 AllowedIPs、endpoint 自身防火墙、`ip_forward` |
| 整个 forward 断了（Docker/容器出站） | `nft list chain inet goremote forward` | 出现无条件规则 = 表被改坏：按第 3 节回滚 |
| `endpoint_warning` 非空 | 设置里的 `public_host` | 填公网地址或域名后重试绑定 |

## 5. 已知边界

- 阶段 1 的 ACL 只区分角色（client / endpoint），**client→endpoint 是全端口放行**；要按端口收窄是阶段 2。
- 不与 Docker 争优先级：本表 `priority 0` 且只 jump wg 流量，其它 base chain 的 verdict 不受影响。
- 监控/告警不包含本表；`acl_ready` 与 `infra_error` 是唯一的状态出口。
