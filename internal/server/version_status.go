package server

import "goremote/internal/buildinfo"

// agentVersionOutdated 报告 agent 的版本是否落后于服务端。
//
// 规则（写死在这里，避免面板/接口各有一套判断）：
//   - 任一侧不可解析（dev、unknown、空）→ false。无法比较不等于落后；
//   - agent < server → true；相等或 agent 更新 → false（那是服务端该升级）；
//   - 预发布后缀（-rc1）与构建后缀（+dirty）不参与排序，见 buildinfo.Parse。
//
// 每次请求现算、不落盘：服务端升级后所有设备立刻按新版本比较，不用等 agent
// 重连一次。
func agentVersionOutdated(agentVersion, serverVersion string) bool {
	agent, ok := buildinfo.Parse(agentVersion)
	if !ok {
		return false
	}
	server, ok := buildinfo.Parse(serverVersion)
	if !ok {
		return false
	}
	for index := 0; index < len(agent); index++ {
		if agent[index] != server[index] {
			return agent[index] < server[index]
		}
	}
	return false
}
