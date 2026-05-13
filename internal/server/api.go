package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
)

func (s *Server) handleAPIClients(c *gin.Context) {
	clients := s.clients.List()
	c.JSON(http.StatusOK, map[string]interface{}{
		"clients": clients,
		"total":   len(clients),
	})
}

func (s *Server) handleAPIClientDetail(c *gin.Context) {
	clientID := c.Param("id")

	client, ok := s.clients.Get(clientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	c.JSON(http.StatusOK, client)
}

type TunnelRequest struct {
	ClientID  string `json:"client_id"`
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	Protocol  string `json:"protocol"`
}

func (s *Server) advertisedTunnelHost(reqHost string) string {
	if s.config.Tunnel.PublicHost != "" {
		return s.config.Tunnel.PublicHost
	}

	if host, _, err := net.SplitHostPort(reqHost); err == nil && host != "" {
		return host
	}

	if reqHost != "" {
		return reqHost
	}

	if host := s.config.Server.Host; host != "" && host != "0.0.0.0" && host != "::" {
		return host
	}

	return "127.0.0.1"
}

func tunnelPublicAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func (s *Server) handleAPICreateTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	var req TunnelRequest
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.ClientID == "" || req.LocalPort == 0 {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "client_id and local_port are required"})
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.LocalAddr == "" {
		req.LocalAddr = s.config.Tunnel.DefaultLocalAddr
	}

	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found or offline"})
		return
	}

	publicPort, err := s.tunnelManager.AllocatePort()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "no available ports"})
		return
	}

	tunnelID := generateUUID()

	if err := s.tunnelManager.CreateTunnel(
		tunnelID,
		req.ClientID,
		client,
		req.Protocol,
		req.LocalAddr,
		req.LocalPort,
		publicPort,
	); err != nil {
		s.tunnelManager.ReleasePort(publicPort)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if err := s.tunnelManager.Listen(publicPort, tunnelID); err != nil {
		s.tunnelManager.CloseTunnel(tunnelID)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	tunnelOpenPayload := common.TunnelOpenPayload{
		TunnelID:  tunnelID,
		LocalAddr: req.LocalAddr,
		LocalPort: req.LocalPort,
		Protocol:  req.Protocol,
	}
	payloadJSON, _ := json.Marshal(tunnelOpenPayload)
	err = client.WriteJSON(common.Message{
		Type:    "tunnel_open",
		Payload: payloadJSON,
	})
	if err != nil {
		s.tunnelManager.CloseTunnel(tunnelID)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send tunnel_open to agent"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"tunnel_id":   tunnelID,
		"public_port": publicPort,
		"public_addr": tunnelPublicAddr(s.advertisedTunnelHost(c.Request.Host), publicPort),
		"local_addr":  req.LocalAddr,
		"status":      "active",
	})
}

func (s *Server) handleAPIListTunnels(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	tunnels := s.tunnelManager.ListTunnels()
	c.JSON(http.StatusOK, map[string]interface{}{
		"tunnels": tunnels,
		"total":   len(tunnels),
	})
}

func (s *Server) handleAPIGetTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	tunnelID := c.Param("tunnel_id")
	tunnel, ok := s.tunnelManager.GetTunnel(tunnelID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleAPIDeleteTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	tunnelID := c.Param("tunnel_id")
	tunnel, ok := s.tunnelManager.GetTunnel(tunnelID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}

	tunnelClosePayload := common.TunnelClosePayload{
		TunnelID: tunnelID,
	}
	payloadJSON, _ := json.Marshal(tunnelClosePayload)
	tunnel.Client.WriteJSON(common.Message{
		Type:    "tunnel_close",
		Payload: payloadJSON,
	})

	if err := s.tunnelManager.CloseTunnel(tunnelID); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{"success": "true"})
}

func (s *Server) handleAPIUpdateTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	tunnelID := c.Param("tunnel_id")

	var req struct {
		LocalAddr  string `json:"local_addr"`
		LocalPort  int    `json:"local_port"`
		PublicPort int    `json:"public_port"`
		Protocol   string `json:"protocol"`
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.LocalPort == 0 {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "local_port is required"})
		return
	}

	if req.LocalAddr == "" {
		req.LocalAddr = s.config.Tunnel.DefaultLocalAddr
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	tunnel, err := s.tunnelManager.UpdateTunnel(tunnelID, req.LocalAddr, req.LocalPort, req.PublicPort, req.Protocol)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleAPIListClientTunnels(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	clientID := c.Param("client_id")
	tunnels := s.tunnelManager.ListTunnelsByClient(clientID)
	c.JSON(http.StatusOK, map[string]interface{}{
		"tunnels": tunnels,
		"total":   len(tunnels),
	})
}

func (s *Server) handleAPIPortStatus(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "tunnel is not enabled"})
		return
	}

	status := s.tunnelManager.GetPortStatus()
	c.JSON(http.StatusOK, status)
}

// handleAPIGetWhitelist returns the IP whitelist for a specific client.
// @Summary 获取客户端IP白名单
// @Description 获取指定客户端的IP白名单列表
// @Tags clients
// @Produce json
// @Param id path string true "客户端ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]string
// @Router /api/clients/{id}/whitelist [get]
func (s *Server) handleAPIGetWhitelist(c *gin.Context) {
	clientID := c.Param("id")

	client, ok := s.clients.Get(clientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"client_id":    client.ClientID,
		"hostname":     client.Hostname,
		"ip_whitelist": client.IPWhitelist,
	})
}

// handleAPIUpdateWhitelist updates the IP whitelist for a specific client.
// @Summary 更新客户端IP白名单
// @Description 设置指定客户端的IP白名单（覆盖），白名单中的IP不受限流限制
// @Tags clients
// @Accept json
// @Produce json
// @Param id path string true "客户端ID"
// @Param body body object true "IP白名单"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/clients/{id}/whitelist [put]
func (s *Server) handleAPIUpdateWhitelist(c *gin.Context) {
	clientID := c.Param("id")

	client, ok := s.clients.Get(clientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	var req struct {
		IPs []string `json:"ips"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	s.clients.SetIPWhitelist(clientID, req.IPs)

	c.JSON(http.StatusOK, map[string]interface{}{
		"client_id":    client.ClientID,
		"hostname":     client.Hostname,
		"ip_whitelist": s.clients.GetIPWhitelist(clientID),
	})
}

func (s *Server) handleAPIGetGlobalWhitelist(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"global_whitelist": s.GetGlobalWhitelist(),
	})
}

func (s *Server) handleAPIUpdateGlobalWhitelist(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	s.SetGlobalWhitelist(req.IPs)

	c.JSON(http.StatusOK, map[string]interface{}{
		"global_whitelist": s.GetGlobalWhitelist(),
	})
}

func (s *Server) handleAPIGetBlacklist(c *gin.Context) {
	entries := s.blacklist.List()
	violations := s.blacklist.AllViolations()
	c.JSON(http.StatusOK, map[string]interface{}{
		"blacklist":  entries,
		"violations": violations,
		"threshold":  s.blacklist.GetThreshold(),
	})
}

func (s *Server) handleAPIAddBlacklist(c *gin.Context) {
	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration int    `json:"duration_minutes"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.IP == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "ip is required"})
		return
	}

	if net.ParseIP(req.IP) == nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "manual"
	}

	var duration time.Duration
	if req.Duration > 0 {
		duration = time.Duration(req.Duration) * time.Minute
	}

	s.blacklist.AddManual(req.IP, reason, duration)

	c.JSON(http.StatusOK, map[string]interface{}{
		"ip":      req.IP,
		"reason":  reason,
		"message": "IP added to blacklist",
	})
}

func (s *Server) handleAPIRemoveBlacklist(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "ip is required"})
		return
	}

	s.blacklist.Remove(ip)
	c.JSON(http.StatusOK, map[string]string{"message": "IP removed from blacklist"})
}

func (s *Server) handleAPIGetBlacklistThreshold(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"threshold": s.blacklist.GetThreshold(),
	})
}

func (s *Server) handleAPIUpdateBlacklistThreshold(c *gin.Context) {
	var req struct {
		Threshold int `json:"threshold"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Threshold < 0 {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "threshold must be >= 0"})
		return
	}

	s.blacklist.SetThreshold(req.Threshold)

	c.JSON(http.StatusOK, map[string]interface{}{
		"threshold": s.blacklist.GetThreshold(),
	})
}
