package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"goremote/internal/common"
)

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if !s.adminAuth.Login(req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	token, _ := s.adminAuth.GenerateToken()
	c.SetCookie("go_remote_token", token, 86400, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "token": token})
}

func (s *Server) handleLogout(c *gin.Context) {
	token, _ := c.Cookie("go_remote_token")
	if token != "" {
		s.adminAuth.Logout(token)
	}
	c.SetCookie("go_remote_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleCheckAuth(c *gin.Context) {
	token, _ := c.Cookie("go_remote_token")
	if s.adminAuth.Validate(token) {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"authenticated": false})
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, _ := c.Cookie("go_remote_token")
		if s.adminAuth.Validate(token) {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if path == "/login.html" {
			c.Next()
			return
		}

		if c.GetHeader("Accept") == "application/json" || len(path) >= 4 && path[:4] == "/api" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Redirect(http.StatusFound, "/login.html")
		c.Abort()
	}
}

type TunnelRequest struct {
	ClientID  string `json:"client_id"`
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	Protocol  string `json:"protocol"`
}

func (s *Server) handleAPIClients(c *gin.Context) {
	type clientInfo struct {
		ClientID string    `json:"client_id"`
		Hostname string    `json:"hostname"`
		OS       string    `json:"os"`
		RegTime  time.Time `json:"reg_time"`
		LastPing time.Time `json:"last_ping"`
		Online   bool      `json:"online"`
	}

	clients := s.clients.List()
	onlineClients := make([]clientInfo, 0, len(clients))
	for _, cl := range clients {
		device := s.stateStore.GetDeviceByID(cl.ClientID)
		hostname := cl.Hostname
		osName := cl.OS
		if device != nil {
			hostname = device.Hostname
			osName = device.OS
		}
		onlineClients = append(onlineClients, clientInfo{
			ClientID: cl.ClientID,
			Hostname: hostname,
			OS:       osName,
			RegTime:  cl.RegTime,
			LastPing: cl.LastPing,
			Online:   true,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"clients": onlineClients,
		"total":   len(onlineClients),
	})
}

func (s *Server) handleAPIClientDetail(c *gin.Context) {
	clientID := c.Param("id")

	client, ok := s.clients.Get(clientID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}

	c.JSON(http.StatusOK, client)
}

func (s *Server) handleAPIListClientTunnels(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return
	}

	clientID := c.Param("client_id")
	tunnels := s.tunnelManager.ListTunnelsByClient(clientID)
	c.JSON(http.StatusOK, gin.H{
		"tunnels": tunnels,
		"total":   len(tunnels),
	})
}

func (s *Server) handleAPICreateTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return
	}

	var req TunnelRequest
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	if req.ClientID == "" || req.LocalPort == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id and local_port are required"})
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	settings := s.stateStore.GetSettings()
	if req.LocalAddr == "" {
		req.LocalAddr = settings.DefaultLocalAddr
	}

	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found or offline"})
		return
	}

	publicPort, err := s.tunnelManager.AllocatePort()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no available ports"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := s.tunnelManager.Listen(publicPort, tunnelID); err != nil {
		s.tunnelManager.CloseTunnel(tunnelID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	tunnelOpenPayload := common.TunnelOpenPayload{
		TunnelID:  tunnelID,
		LocalAddr: req.LocalAddr,
		LocalPort: req.LocalPort,
		Protocol:  req.Protocol,
	}
	payloadJSON, _ := json.Marshal(tunnelOpenPayload)
	if err := client.WriteJSON(common.Message{
		Type:    "tunnel_open",
		Payload: payloadJSON,
	}); err != nil {
		s.tunnelManager.CloseTunnel(tunnelID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send tunnel_open to agent"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tunnel_id":   tunnelID,
		"public_port": publicPort,
		"public_addr": tunnelPublicAddr(s.advertisedTunnelHost(c.Request.Host), publicPort),
		"local_addr":  req.LocalAddr,
		"status":      "active",
	})
}

func (s *Server) advertisedTunnelHost(reqHost string) string {
	settings := s.stateStore.GetSettings()
	if settings.PublicHost != "" {
		return settings.PublicHost
	}

	if host, _, err := net.SplitHostPort(reqHost); err == nil && host != "" {
		return host
	}

	if reqHost != "" {
		return reqHost
	}

	if s.config.Server.Host != "" && s.config.Server.Host != "0.0.0.0" && s.config.Server.Host != "::" {
		return s.config.Server.Host
	}

	return "127.0.0.1"
}

func tunnelPublicAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func (s *Server) handleAPIListTunnels(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return
	}

	tunnels := s.tunnelManager.ListTunnels()
	c.JSON(http.StatusOK, gin.H{
		"tunnels": tunnels,
		"total":   len(tunnels),
	})
}

func (s *Server) handleAPIGetTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return
	}

	tunnelID := c.Param("tunnel_id")
	tunnel, ok := s.tunnelManager.GetTunnel(tunnelID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleAPIDeleteTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return
	}

	tunnelID := c.Param("tunnel_id")
	tunnel, ok := s.tunnelManager.GetTunnel(tunnelID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		return
	}

	tunnelClosePayload := common.TunnelClosePayload{TunnelID: tunnelID}
	payloadJSON, _ := json.Marshal(tunnelClosePayload)
	tunnel.Client.WriteJSON(common.Message{
		Type:    "tunnel_close",
		Payload: payloadJSON,
	})

	if err := s.tunnelManager.CloseTunnel(tunnelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) handleAPIUpdateTunnel(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	if req.LocalPort == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "local_port is required"})
		return
	}

	settings := s.stateStore.GetSettings()
	if req.LocalAddr == "" {
		req.LocalAddr = settings.DefaultLocalAddr
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	tunnel, err := s.tunnelManager.UpdateTunnel(tunnelID, req.LocalAddr, req.LocalPort, req.PublicPort, req.Protocol)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleAPIGetWhitelist(c *gin.Context) {
	clientID := c.Param("id")
	device := s.stateStore.GetDeviceByID(clientID)
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"client_id":    clientID,
		"hostname":     device.Hostname,
		"ip_whitelist": device.IPWhitelist,
	})
}

func (s *Server) handleAPIUpdateWhitelist(c *gin.Context) {
	clientID := c.Param("id")
	device := s.stateStore.GetDeviceByID(clientID)
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	var req struct {
		IPs []string `json:"ips"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	deduped := deduplicateIPs(req.IPs)
	s.stateStore.UpdateDevice(clientID, func(d *DeviceState) {
		d.IPWhitelist = deduped
	})

	c.JSON(http.StatusOK, gin.H{
		"client_id":    clientID,
		"hostname":     device.Hostname,
		"ip_whitelist": deduped,
	})
}

func (s *Server) handleAPIGetGlobalWhitelist(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"global_whitelist": s.GetGlobalWhitelist(),
	})
}

func (s *Server) handleAPIUpdateGlobalWhitelist(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	s.SetGlobalWhitelist(req.IPs)

	c.JSON(http.StatusOK, gin.H{
		"global_whitelist": s.GetGlobalWhitelist(),
	})
}

func (s *Server) handleAPIGetBlacklist(c *gin.Context) {
	entries := s.blacklist.List()
	violations := s.blacklist.AllViolations()
	c.JSON(http.StatusOK, gin.H{
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	if net.ParseIP(req.IP) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP address"})
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

	c.JSON(http.StatusOK, gin.H{
		"ip":      req.IP,
		"reason":  reason,
		"message": "IP added to blacklist",
	})
}

func (s *Server) handleAPIRemoveBlacklist(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	s.blacklist.Remove(ip)
	c.JSON(http.StatusOK, gin.H{"message": "IP removed from blacklist"})
}

func (s *Server) handleAPIGetBlacklistThreshold(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"threshold": s.blacklist.GetThreshold(),
	})
}

func (s *Server) handleAPIUpdateBlacklistThreshold(c *gin.Context) {
	var req struct {
		Threshold int `json:"threshold"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	if req.Threshold < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threshold must be >= 0"})
		return
	}

	s.blacklist.SetThreshold(req.Threshold)

	c.JSON(http.StatusOK, gin.H{
		"threshold": s.blacklist.GetThreshold(),
	})
}

func (s *Server) handleAPIPortStatus(c *gin.Context) {
	if s.tunnelManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tunnel is not enabled"})
		return
	}

	status := s.tunnelManager.GetPortStatus()
	c.JSON(http.StatusOK, status)
}

func (s *Server) handleAPIListDevices(c *gin.Context) {
	devices := s.stateStore.GetAllDevices()
	type deviceInfo struct {
		ID              string    `json:"id"`
		Name            string    `json:"name"`
		Hostname        string    `json:"hostname"`
		OS              string    `json:"os"`
		Status          string    `json:"status"`
		EncEnabled      bool      `json:"enc_enabled"`
		FirstSeen       time.Time `json:"first_seen"`
		ApprovedAt      *time.Time `json:"approved_at,omitempty"`
		Online          bool      `json:"online"`
	}

	result := make([]deviceInfo, 0, len(devices))
	for _, d := range devices {
		_, online := s.clients.Get(d.ID)
		result = append(result, deviceInfo{
			ID:         d.ID,
			Name:       d.Name,
			Hostname:   d.Hostname,
			OS:         d.OS,
			Status:     d.Status,
			EncEnabled: d.EncEnabled,
			FirstSeen:  d.FirstSeen,
			ApprovedAt: d.ApprovedAt,
			Online:     online,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"devices": result,
		"total":   len(result),
	})
}

func (s *Server) handleAPIListPendingDevices(c *gin.Context) {
	pending := s.stateStore.GetDevicesByStatus("pending")
	type pendingInfo struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Hostname  string    `json:"hostname"`
		OS        string    `json:"os"`
		FirstSeen time.Time `json:"first_seen"`
		RemoteIP  string    `json:"remote_ip"`
	}

	result := make([]pendingInfo, 0, len(pending))
	for _, d := range pending {
		remoteIP := ""
		if conn, ok := s.deviceMgr.GetPendingConn(d.ID); ok {
			remoteIP = conn.RemoteIP
		}
		result = append(result, pendingInfo{
			ID:        d.ID,
			Name:      d.Name,
			Hostname:  d.Hostname,
			OS:        d.OS,
			FirstSeen: d.FirstSeen,
			RemoteIP:  remoteIP,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"devices": result,
		"total":   len(result),
	})
}

func (s *Server) handleAPIApproveDevice(c *gin.Context) {
	deviceID := c.Param("id")

	device, encKeyEncrypted, serverDHPubkey, err := s.deviceMgr.ApproveDevice(deviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if conn, ok := s.deviceMgr.GetPendingConn(deviceID); ok {
		wsConn := conn.Conn.(*websocket.Conn)
		okPayload := common.RegisterOKPayload{
			ClientID:        deviceID,
			EncKeyEncrypted: encKeyEncrypted,
			ServerDHPubkey:  serverDHPubkey,
			EncEnabled:      device.EncEnabled,
		}
		payloadJSON, _ := json.Marshal(okPayload)
		wsConn.WriteJSON(common.Message{
			Type:    "register_ok",
			Payload: payloadJSON,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "approved",
	})
}

func (s *Server) handleAPIDenyDevice(c *gin.Context) {
	deviceID := c.Param("id")

	if conn, ok := s.deviceMgr.GetPendingConn(deviceID); ok {
		wsConn := conn.Conn.(*websocket.Conn)
		failPayload := common.RegisterFailPayload{Reason: "registration denied by admin"}
		payloadJSON, _ := json.Marshal(failPayload)
		wsConn.WriteJSON(common.Message{
			Type:    "register_fail",
			Payload: payloadJSON,
		})
		wsConn.Close()
	}

	if err := s.deviceMgr.DenyDevice(deviceID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "denied",
	})
}

func (s *Server) handleAPIDeleteDevice(c *gin.Context) {
	deviceID := c.Param("id")

	if client, ok := s.clients.Get(deviceID); ok {
		delPayload := common.DeviceDeletedPayload{Reason: "device deleted by admin"}
		payloadJSON, _ := json.Marshal(delPayload)
		client.WriteJSON(common.Message{
			Type:    "device_deleted",
			Payload: payloadJSON,
		})
		client.Conn.Close()
		s.clients.Remove(deviceID)
	}

	if err := s.deviceMgr.DeleteDevice(deviceID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "deleted",
	})
}

func (s *Server) handleAPIUpdateDeviceConfig(c *gin.Context) {
	deviceID := c.Param("id")

	var req struct {
		Name         string   `json:"name"`
		EncEnabled   *bool    `json:"enc_enabled"`
		IPWhitelist  []string `json:"ip_whitelist"`
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	encEnabled := false
	if req.EncEnabled != nil {
		encEnabled = *req.EncEnabled
	} else {
		device := s.stateStore.GetDeviceByID(deviceID)
		if device != nil {
			encEnabled = device.EncEnabled
		}
	}

	device, err := s.deviceMgr.UpdateDeviceConfig(deviceID, req.Name, encEnabled, req.IPWhitelist)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id":    device.ID,
		"name":         device.Name,
		"enc_enabled":  device.EncEnabled,
		"ip_whitelist": device.IPWhitelist,
	})
}

func (s *Server) handleAPIRegenKey(c *gin.Context) {
	deviceID := c.Param("id")

	device, encKeyEncrypted, serverDHPubkey, err := s.deviceMgr.RegenerateEncKey(deviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if client, ok := s.clients.Get(deviceID); ok {
		updatePayload := common.RegisterUpdatePayload{
			Type:            "enc_key_update",
			EncKeyEncrypted: encKeyEncrypted,
			ServerDHPubkey:  serverDHPubkey,
			EncEnabled:      device.EncEnabled,
		}
		payloadJSON, _ := json.Marshal(updatePayload)
		client.WriteJSON(common.Message{
			Type:    "register_update",
			Payload: payloadJSON,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": deviceID,
		"status":    "key_regenerated",
	})
}

func (s *Server) handleAPIGetSettings(c *gin.Context) {
	settings := s.stateStore.GetSettings()
	c.JSON(http.StatusOK, settings)
}

func (s *Server) handleAPIUpdateSettings(c *gin.Context) {
	var req ServerSettings
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	s.stateStore.UpdateSettings(func(st *ServerSettings) {
		if req.PortRangeStart > 0 {
			st.PortRangeStart = req.PortRangeStart
		}
		if req.PortRangeEnd > 0 {
			st.PortRangeEnd = req.PortRangeEnd
		}
		if req.MaxTunnelsPerClient > 0 {
			st.MaxTunnelsPerClient = req.MaxTunnelsPerClient
		}
		if req.DefaultLocalAddr != "" {
			st.DefaultLocalAddr = req.DefaultLocalAddr
		}
		if req.MaxConnPerMin > 0 {
			st.MaxConnPerMin = req.MaxConnPerMin
		}
		if req.LoginRateLimit > 0 {
			st.LoginRateLimit = req.LoginRateLimit
		}
		if req.BlacklistThreshold > 0 {
			st.BlacklistThreshold = req.BlacklistThreshold
		}
		if req.MaxBodySizeMB > 0 {
			st.MaxBodySizeMB = req.MaxBodySizeMB
		}
		if req.HeartbeatInterval > 0 {
			st.HeartbeatInterval = req.HeartbeatInterval
		}
		if req.HeartbeatTimeout > 0 {
			st.HeartbeatTimeout = req.HeartbeatTimeout
		}
		if req.GlobalWhitelist != nil {
			st.GlobalWhitelist = req.GlobalWhitelist
		}
	})

	c.JSON(http.StatusOK, s.stateStore.GetSettings())
}