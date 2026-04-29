package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

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
		LocalAddr string `json:"local_addr"`
		LocalPort int    `json:"local_port"`
		Protocol  string `json:"protocol"`
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

	tunnel, err := s.tunnelManager.UpdateTunnel(tunnelID, req.LocalAddr, req.LocalPort, req.Protocol)
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
