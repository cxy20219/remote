package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"
)

// 审计日志：不新建日志系统，直接走现有 slog handler（跟随日志轮转与 journal
// 采集）。每条固定带 audit=true 与 event，公共信封回答「谁、什么时候、从哪个
// IP、对什么对象、做了什么、结果如何」。
//
// 硬约束：绝不把令牌、密钥、cookie、恢复码写进审计。会话只记 token 的
// sha256 前 8 位，用来把同一会话的多个操作串起来，但不还原成 token 本身。
const (
	auditMessage        = "audit"
	auditActorAdmin     = "admin"
	auditActorSystem    = "system"
	auditActorAgentBase = "agent:"

	// 与 setAdminCookie 写的是同一个 Cookie；这里只取来做指纹。
	adminSessionCookieName = "go_remote_token"
)

// 审计事件名是契约：面板、grep、测试都按这些名字找，不要临时发明。
const (
	auditEventAdminLogin          = "admin.login"
	auditEventAdminLoginFailed    = "admin.login.failed"
	auditEventAdminPasswordChange = "admin.password.change"
	auditEventAdminTOTPEnable     = "admin.totp.enable"
	auditEventAdminTOTPDisable    = "admin.totp.disable"
	auditEventAdminTOTPRecover    = "admin.totp.recover"
	auditEventTunnelCreate        = "tunnel.create"
	auditEventTunnelUpdate        = "tunnel.update"
	auditEventTunnelDelete        = "tunnel.delete"
	auditEventTunnelRetry         = "tunnel.retry"
	auditEventTunnelApplyFailed   = "tunnel.apply.failed"
	auditEventDeviceApprove       = "device.approve"
	auditEventDeviceDeny          = "device.deny"
	auditEventDeviceDelete        = "device.delete"
	auditEventDeviceReauthReject  = "device.reauth.rejected"
	auditEventSettingsUpdate      = "settings.update"
	auditEventBlacklistAdd        = "blacklist.add"
	auditEventBlacklistRemove     = "blacklist.remove"
	auditEventServerStart         = "server.start"
	auditEventServerStop          = "server.stop"
)

// auditRecord 是唯一的写入点：event 与信封字段在前，调用方的 detail 在后。
func auditRecord(level slog.Level, attrs []slog.Attr) {
	slog.LogAttrs(context.Background(), level, auditMessage, attrs...)
}

// auditEnvelope 组装公共信封。
func auditEnvelope(event, actor, ip, session, object, action, result, reason string) []slog.Attr {
	attrs := []slog.Attr{
		slog.Bool("audit", true),
		slog.String("event", event),
		slog.String("actor", actor),
	}
	if ip != "" {
		attrs = append(attrs, slog.String("ip", ip))
	}
	if session != "" {
		attrs = append(attrs, slog.String("session", session))
	}
	if object != "" {
		attrs = append(attrs, slog.String("object", object))
	}
	if action != "" {
		attrs = append(attrs, slog.String("action", action))
	}
	if result != "" {
		attrs = append(attrs, slog.String("result", result))
	}
	if reason != "" {
		attrs = append(attrs, slog.String("reason", reason))
	}
	return attrs
}

// auditRequest 记录一次由管理员 HTTP 请求触发的操作。result 为 "ok" 时记 INFO，
// 否则记 WARN（失败与拒绝要能在默认日志级别下看见）。
func auditRequest(c *gin.Context, event, object, action, result, reason string, extra ...slog.Attr) {
	session := ""
	if c != nil {
		session = auditSessionID(c)
	}
	auditRequestSession(c, session, event, object, action, result, reason, extra...)
}

// auditRequestSession 与 auditRequest 相同，但显式给会话指纹：登录刚下发 Cookie
// 的那一刻请求里还没有它（gin 的 SetCookie 只写响应头），只能由签发方传入。
func auditRequestSession(c *gin.Context, session, event, object, action, result, reason string, extra ...slog.Attr) {
	ip := ""
	if c != nil {
		ip = c.ClientIP()
	}
	attrs := auditEnvelope(event, auditActorAdmin, ip, session, object, action, result, reason)
	attrs = append(attrs, extra...)
	level := slog.LevelWarn
	if result == "ok" {
		level = slog.LevelInfo
	}
	auditRecord(level, attrs)
}

// auditSystem 记录系统侧事件（启动/关闭/自动封禁/隧道绑定失败）：没有请求上下文，
// actor 固定为 system。
func auditSystem(event, object, action, result, reason string, extra ...slog.Attr) {
	attrs := auditEnvelope(event, auditActorSystem, "", "", object, action, result, reason)
	attrs = append(attrs, extra...)
	level := slog.LevelWarn
	if result == "ok" {
		level = slog.LevelInfo
	}
	auditRecord(level, attrs)
}

// auditMaxFieldLength 是审计里外部可控字符串（设备 ID、error 文案）的上限。
// agent 的 ClientID 最长可以顶到 WS 报文上限，不截断就能用一条注册报文把日志撑大。
const auditMaxFieldLength = 128

// truncateForAudit 截断外部可控字符串，避免单条审计被撑爆。
func truncateForAudit(value string) string {
	if len(value) <= auditMaxFieldLength {
		return value
	}
	return value[:auditMaxFieldLength] + "…"
}

// auditAgent 记录 agent 侧的安全事件（reauth 被拒），actor 是设备 ID。
func auditAgent(deviceID, ip, event, object, action, result, reason string, extra ...slog.Attr) {
	deviceID = truncateForAudit(deviceID)
	object = truncateForAudit(object)
	attrs := auditEnvelope(event, auditActorAgentBase+deviceID, ip, "", object, action, result, reason)
	attrs = append(attrs, extra...)
	auditRecord(slog.LevelWarn, attrs)
}

// auditSessionID 返回当前会话的指纹（token 的 sha256 前 8 位），拿不到会话时为空。
func auditSessionID(c *gin.Context) string {
	token, err := c.Cookie(adminSessionCookieName)
	if err != nil {
		return ""
	}
	return auditFingerprint(token)
}

// auditFingerprint 是会话指纹的唯一定义：sha256 前 8 位十六进制。
func auditFingerprint(token string) string {
	if strings.TrimSpace(token) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}
