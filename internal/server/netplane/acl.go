package netplane

import (
	"fmt"
	"sort"
	"strings"
)

// buildACL 把期望 peer 渲染成 nft 集合。只有启用的、有地址的 peer 进入集合；
// 角色决定进 clients 还是 endpoints。
func buildACL(snapshot Snapshot) ACL {
	interfaceName := snapshot.Hub.Interface
	if interfaceName == "" {
		interfaceName = DefaultInterface
	}
	acl := ACL{Interface: interfaceName}
	for _, peer := range snapshot.Peers {
		if !peer.Enabled || peer.Address == "" {
			continue
		}
		address := peer.Address
		if !strings.Contains(address, "/") {
			address += "/32"
		}
		if peer.Role == "endpoint" {
			acl.Endpoints = append(acl.Endpoints, address)
		} else {
			acl.Clients = append(acl.Clients, address)
		}
	}
	sort.Strings(acl.Clients)
	sort.Strings(acl.Endpoints)
	return acl
}

// signature 用于判断 ACL 是否真的变了：没变就不重载表，避免每次 peer 变更
// 都把 nft 计数器清零（排障时要看 drop 有没有增长）。
func (a ACL) signature() string {
	return a.Interface + "|clients|" + strings.Join(a.Clients, ",") +
		"|endpoints|" + strings.Join(a.Endpoints, ",")
}

// buildACLTable 生成整张表的 nft 文本，交给 `nft -f` 在**一个内核事务**里
// 提交：先 add（幂等，表不存在时创建）、再 delete、再完整定义，因此不存在
// 半套规则；任何一行语法/内核错误都会让整批回滚。
//
// 结构按设计 §6：两条 jump 都带 iifname/oifname 限定，链尾 drop 只作用于
// wg 流量，base chain 上没有任何无条件规则——否则 Docker DNAT / 容器出站 /
// 所有本机转发都会被一起切断。
func buildACLTable(acl ACL) string {
	interfaceName := acl.Interface
	if interfaceName == "" {
		interfaceName = DefaultInterface
	}

	var builder strings.Builder
	builder.WriteString("add table inet goremote\n")
	builder.WriteString("delete table inet goremote\n")
	builder.WriteString("table inet goremote {\n")
	writeACLSet(&builder, "clients", acl.Clients)
	writeACLSet(&builder, "endpoints", acl.Endpoints)

	// forward：只把 wg 进/出的流量送进本表的 ACL 链；policy accept 保证其它
	// 表（Docker/firewalld）的转发不受影响。
	fmt.Fprintf(&builder, "\tchain forward {\n")
	fmt.Fprintf(&builder, "\t\ttype filter hook forward priority 0; policy accept;\n")
	fmt.Fprintf(&builder, "\t\tiifname %q jump wg_fwd\n", interfaceName)
	fmt.Fprintf(&builder, "\t\toifname %q jump wg_fwd_rev\n", interfaceName)
	fmt.Fprintf(&builder, "\t}\n")

	// wg_fwd：从 wg 进来的包。回程连接（client 发起、endpoint 回）靠
	// established/related 放行；新连接只放 client→endpoint 的 TCP/UDP 和
	// echo-request；其余（client→client、endpoint→client、client→hub 地址、
	// VPC/元数据）全部 drop。
	builder.WriteString("\tchain wg_fwd {\n")
	builder.WriteString("\t\tct state established,related accept\n")
	builder.WriteString("\t\tmeta l4proto { tcp, udp } ip saddr @clients ip daddr @endpoints counter accept\n")
	builder.WriteString("\t\ticmp type echo-request ip saddr @clients ip daddr @endpoints accept\n")
	builder.WriteString("\t\tcounter drop\n")
	builder.WriteString("\t}\n")

	// wg_fwd_rev：发往 wg 接口、不是从 wg 进来的流量（Docker/VPC/本机 LAN）。
	// 只放 established/related，新连接全 drop——包括伪造源地址的包。
	builder.WriteString("\tchain wg_fwd_rev {\n")
	builder.WriteString("\t\tct state established,related accept\n")
	builder.WriteString("\t\tcounter drop\n")
	builder.WriteString("\t}\n")

	// input：wg 进来的流量不能摸 hub 自身的面板/SSH。
	builder.WriteString("\tchain input {\n")
	builder.WriteString("\t\ttype filter hook input priority 0; policy accept;\n")
	fmt.Fprintf(&builder, "\t\tiifname %q jump wg_in\n", interfaceName)
	builder.WriteString("\t}\n")
	builder.WriteString("\tchain wg_in {\n")
	builder.WriteString("\t\tct state established,related accept\n")
	builder.WriteString("\t\ticmp type echo-request accept\n")
	builder.WriteString("\t\tcounter drop\n")
	builder.WriteString("\t}\n")

	builder.WriteString("}\n")
	return builder.String()
}

func writeACLSet(builder *strings.Builder, name string, elements []string) {
	fmt.Fprintf(builder, "\tset %s {\n", name)
	builder.WriteString("\t\ttype ipv4_addr\n")
	builder.WriteString("\t\tflags interval\n")
	if len(elements) > 0 {
		fmt.Fprintf(builder, "\t\telements = { %s }\n", strings.Join(elements, ", "))
	}
	builder.WriteString("\t}\n")
}
