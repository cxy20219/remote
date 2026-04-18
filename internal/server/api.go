package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"goremote/internal/common"
)

// handleAPIClients 获取在线客户端列表
// @Summary 获取在线客户端列表
// @Description 获取所有当前在线的客户端列表
// @Tags clients
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/clients [get]
func (s *Server) handleAPIClients(c *gin.Context) {
	clients := s.clients.List()
	c.JSON(http.StatusOK, map[string]interface{}{
		"clients": clients,
		"total":   len(clients),
	})
}

// handleAPIClientDetail 获取客户端详情
// @Summary 获取客户端详情
// @Description 根据客户端ID获取详细信息
// @Tags clients
// @Produce json
// @Param id path string true "客户端ID"
// @Success 200 {object} Client
// @Failure 404 {object} map[string]string
// @Router /api/clients/{id} [get]
func (s *Server) handleAPIClientDetail(c *gin.Context) {
	clientID := c.Param("id")

	client, ok := s.clients.Get(clientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	c.JSON(http.StatusOK, client)
}

// ExecRequest 执行命令请求
type ExecRequest struct {
	ClientID string `json:"client_id"`
	Command  string `json:"command"`
	Timeout  int    `json:"timeout"`
}

// handleAPIExec 向指定客户端下发命令
// @Summary 向指定客户端下发命令
// @Description 向指定客户端下发待执行的命令
// @Tags exec
// @Accept json
// @Produce json
// @Param request body server.ExecRequest true "执行请求"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/exec [post]
func (s *Server) handleAPIExec(c *gin.Context) {
	var req ExecRequest

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.ClientID == "" || req.Command == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "client_id and command are required"})
		return
	}

	if req.Timeout == 0 {
		req.Timeout = 30
	}

	// Generate task ID
	taskID := generateUUID()

	// Create task
	task := &Task{
		TaskID:   taskID,
		ClientID: req.ClientID,
		Command:  req.Command,
		Timeout:  req.Timeout,
	}
	s.tasks.Create(task)

	// Send command to client
	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found or offline"})
		return
	}

	payload := common.ExecPayload{
		TaskID:  taskID,
		Command: req.Command,
		Timeout: req.Timeout,
	}
	payloadJSON, _ := json.Marshal(payload)
	err = client.WriteJSON(common.Message{
		Type:    "exec",
		Payload: payloadJSON,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send command"})
		return
	}

	s.tasks.Update(taskID, StatusRunning)

	c.JSON(http.StatusOK, map[string]string{
		"task_id": taskID,
		"status":  "pending",
	})
}

// handleAPITasks 获取任务列表
// @Summary 获取任务列表
// @Description 获取所有任务列表
// @Tags tasks
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/tasks [get]
func (s *Server) handleAPITasks(c *gin.Context) {
	tasks := s.tasks.List()
	c.JSON(http.StatusOK, map[string]interface{}{
		"tasks": tasks,
		"total": len(tasks),
	})
}

// handleAPITaskDetail 获取任务详情
// @Summary 获取任务详情
// @Description 根据任务ID获取任务详细信息
// @Tags tasks
// @Produce json
// @Param id path string true "任务ID"
// @Success 200 {object} Task
// @Failure 404 {object} map[string]string
// @Router /api/tasks/{id} [get]
func (s *Server) handleAPITaskDetail(c *gin.Context) {
	taskID := c.Param("id")

	task := s.tasks.Get(taskID)
	if task == nil {
		c.JSON(http.StatusNotFound, map[string]string{"error": "task not found"})
		return
	}

	c.JSON(http.StatusOK, task)
}

// OpenClawRequest OpenClaw 会话请求
type OpenClawRequest struct {
	ClientID  string `json:"client_id"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
	Timeout   int    `json:"timeout"`
}

// UploadRequest 文件上传请求 (server -> client)
type UploadRequest struct {
	ClientID   string `json:"client_id"`
	ServerPath string `json:"server_path"` // 服务器上的文件路径
	ClientPath string `json:"client_path"` // 客户端保存路径，不填则使用默认路径
}

// DownloadRequest 文件下载请求 (client -> server)
type DownloadRequest struct {
	ClientID   string `json:"client_id"`
	ClientPath string `json:"client_path"` // 客户端要下载的文件路径
	ServerPath string `json:"server_path"` // 服务器保存路径，不填则使用默认路径
}

// handleOpenClaw OpenClaw 会话接口
// @Summary OpenClaw 会话接口
// @Description 通过 OpenClaw agent 发送会话消息
// @Tags openclaw
// @Accept json
// @Produce json
// @Param request body server.OpenClawRequest true "会话请求"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/openclaw [post]
func (s *Server) handleOpenClaw(c *gin.Context) {
	var req OpenClawRequest

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.ClientID == "" || req.UserID == "" || req.SessionID == "" || req.Message == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "client_id, user_id, session_id, message are required"})
		return
	}

	if req.Timeout == 0 {
		req.Timeout = 30
	}

	// 组合 session-id: user_id_session_id
	sessionID := req.UserID + "_" + req.SessionID

	// 生成命令
	command := fmt.Sprintf("openclaw agent --session-id %s --message '%s'", sessionID, req.Message)

	// Generate task ID
	taskID := generateUUID()

	// Create task
	task := &Task{
		TaskID:   taskID,
		ClientID: req.ClientID,
		Command:  command,
		Timeout:  req.Timeout,
	}
	s.tasks.Create(task)

	// Send command to client
	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found or offline"})
		return
	}

	payload := common.ExecPayload{
		TaskID:  taskID,
		Command: command,
		Timeout: req.Timeout,
	}
	payloadJSON, _ := json.Marshal(payload)
	err = client.WriteJSON(common.Message{
		Type:    "exec",
		Payload: payloadJSON,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send command"})
		return
	}

	s.tasks.Update(taskID, StatusRunning)

	// 返回包含 session_id
	c.JSON(http.StatusOK, map[string]interface{}{
		"task_id":    taskID,
		"session_id": sessionID,
		"status":     "pending",
	})
}

// handleAPIUpload 向指定客户端上传文件
// @Summary 向指定客户端上传文件
// @Description 将文件上传到指定客户端，支持 multipart/form-data 或 JSON
// @Tags file
// @Accept multipart/form-data,application/json
// @Produce json
// @Param file formData file true "要上传的文件"
// @Param client_id formData string true "客户端ID"
// @Param client_path formData string false "客户端保存路径"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/upload [post]
func (s *Server) handleAPIUpload(c *gin.Context) {
	var req UploadRequest
	var fileData []byte
	var filename string
	var fileSize int64

	// 判断请求类型
	contentType := c.ContentType()

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart 模式：从表单获取文件
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "file is required"})
			return
		}

		src, err := file.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to open file"})
			return
		}
		defer src.Close()

		fileData, err = io.ReadAll(src)
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read file"})
			return
		}

		filename = file.Filename
		fileSize = file.Size

		req.ClientID = c.PostForm("client_id")
		req.ClientPath = c.PostForm("client_path")
	} else {
		// JSON 模式：从 body 读取
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
			return
		}

		if err := json.Unmarshal(body, &req); err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		if req.ClientID == "" || req.ServerPath == "" {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "client_id and server_path are required"})
			return
		}

		// JSON 模式需要从服务器读取文件
		f, err := os.Open(req.ServerPath)
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "server file not found"})
			return
		}
		defer f.Close()

		fileData, err = io.ReadAll(f)
		if err != nil {
			c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to read server file"})
			return
		}

		stat, _ := f.Stat()
		filename = stat.Name()
		fileSize = stat.Size()
	}

	// 验证客户端
	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "client_id is required"})
		return
	}

	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found or offline"})
		return
	}

	// 确定客户端保存路径
	clientPath := req.ClientPath
	if clientPath == "" {
		clientPath = filepath.Join(s.config.FileTransfer.UploadPath, filename)
	}

	// 生成文件ID
	fileID := generateUUID()

	// 创建上传记录
	upload := &UploadFile{
		FileID:   fileID,
		Filename: clientPath,
		Size:     fileSize,
		Offset:   0,
		TaskID:   "",
		ClientID: req.ClientID,
		Status:   "in_progress",
	}

	s.uploadManager.Add(upload, false)

	// 发送上传请求到客户端
	payload := common.UploadPayload{
		FileID:   fileID,
		Filename: clientPath,
		Size:     fileSize,
		Offset:   0,
		TaskID:   "",
	}
	payloadJSON, _ := json.Marshal(payload)
	err := client.WriteJSON(common.Message{
		Type:    "upload",
		Payload: payloadJSON,
	})
	if err != nil {
		s.uploadManager.Remove(fileID)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send upload request"})
		return
	}

	// 直接在内存中发送文件数据（避免写临时文件）
	go s.sendFileDataAsync(client, fileID, fileData)

	c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":     fileID,
		"client_id":   req.ClientID,
		"client_path": clientPath,
		"size":        fileSize,
		"status":      "uploading",
	})
}

// sendFileInChunksAsync 异步发送文件到客户端
func (s *Server) sendFileInChunksAsync(client *Client, fileID, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		slog.Error("failed to open file for upload", "file_id", fileID, "error", err)
		return
	}
	defer file.Close()

	stat, _ := file.Stat()
	chunkSize := 64 * 1024 // 64KB per chunk
	buffer := make([]byte, chunkSize)
	offset := int64(0)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			data := base64.StdEncoding.EncodeToString(buffer[:n])
			eof := int64(offset)+int64(n) >= stat.Size()

			uploadDataPayload := common.UploadDataPayload{
				FileID: fileID,
				Offset: offset,
				Data:   data,
				EOF:    eof,
			}
			payloadJSON, _ := json.Marshal(uploadDataPayload)
			err := client.WriteJSON(common.Message{
				Type:    "upload_data",
				Payload: payloadJSON,
			})
			if err != nil {
				slog.Error("failed to send upload data", "file_id", fileID, "error", err)
				return
			}
			offset += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Error("failed to read file for upload", "file_id", fileID, "error", err)
			return
		}
	}

	slog.Info("file upload sent", "file_id", fileID, "size", stat.Size())
}

// sendFileDataAsync 异步发送内存中的文件数据到客户端
func (s *Server) sendFileDataAsync(client *Client, fileID string, data []byte) {
	chunkSize := 64 * 1024 // 64KB per chunk
	offset := int64(0)
	totalSize := int64(len(data))

	for offset < totalSize {
		end := offset + int64(chunkSize)
		if end > totalSize {
			end = totalSize
		}

		chunk := data[offset:end]
		encoded := base64.StdEncoding.EncodeToString(chunk)
		eof := end >= totalSize

		uploadDataPayload := common.UploadDataPayload{
			FileID: fileID,
			Offset: offset,
			Data:   encoded,
			EOF:    eof,
		}
		payloadJSON, _ := json.Marshal(uploadDataPayload)
		err := client.WriteJSON(common.Message{
			Type:    "upload_data",
			Payload: payloadJSON,
		})
		if err != nil {
			slog.Error("failed to send upload data", "file_id", fileID, "error", err)
			return
		}
		offset = end
	}

	slog.Info("file upload sent", "file_id", fileID, "size", totalSize)
}

// handleAPIDownload 从指定客户端下载文件
// @Summary 从指定客户端下载文件
// @Description 从指定客户端下载文件到服务器
// @Description 从指定客户端下载文件到服务器
// @Tags file
// @Accept json
// @Produce json
// @Param request body server.DownloadRequest true "下载请求"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/download [post]
func (s *Server) handleAPIDownload(c *gin.Context) {
	var req DownloadRequest

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.ClientID == "" || req.ClientPath == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "client_id and client_path are required"})
		return
	}

	// 获取客户端
	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found or offline"})
		return
	}

	// 确定服务器保存路径
	serverPath := req.ServerPath
	if serverPath == "" {
		// 使用默认目录，从 client_path 提取文件名
		serverPath = s.config.FileTransfer.DownloadPath
		filename := req.ClientPath
		if idx := strings.LastIndex(filename, "/"); idx >= 0 {
			filename = filename[idx+1:]
		}
		if idx := strings.LastIndex(filename, "\\"); idx >= 0 {
			filename = filename[idx+1:]
		}
		serverPath = filepath.Join(serverPath, filename)
	}

	// 确保保存目录存在
	dir := filepath.Dir(serverPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create directory"})
		return
	}

	// 生成文件ID
	fileID := generateUUID()

	savePath := serverPath

	// 创建上传记录（这里复用 UploadFile 结构来保存下载的文件）
	upload := &UploadFile{
		FileID:   fileID,
		Filename: savePath,
		Size:     0,
		Offset:   0,
		TaskID:   "",
		ClientID: req.ClientID,
		Status:   "in_progress",
	}

	if err := s.uploadManager.Add(upload, true); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create upload record"})
		return
	}

	// 发送下载请求到客户端
	payload := common.DownloadPayload{
		FileID:   fileID,
		Filename: req.ClientPath,
	}
	payloadJSON, _ := json.Marshal(payload)
	err = client.WriteJSON(common.Message{
		Type:    "download",
		Payload: payloadJSON,
	})
	if err != nil {
		s.uploadManager.Remove(fileID)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send download request"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":     fileID,
		"client_id":   req.ClientID,
		"client_path": req.ClientPath,
		"server_path": savePath,
		"status":      "downloading",
	})
}

// handleAPIUploadStatus 获取上传/下载状态
// @Summary 获取文件传输状态
// @Description 根据文件ID获取上传或下载状态
// @Tags file
// @Produce json
// @Param file_id path string true "文件ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]string
// @Router /api/upload/{file_id} [get]
func (s *Server) handleAPIUploadStatus(c *gin.Context) {
	fileID := c.Param("file_id")

	upload := s.uploadManager.Get(fileID)
	if upload == nil {
		c.JSON(http.StatusNotFound, map[string]string{"error": "file transfer not found"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":     upload.FileID,
		"filename":    upload.Filename,
		"size":        upload.Size,
		"transferred": upload.Transferred,
		"status":      upload.Status,
		"client_id":   upload.ClientID,
	})
}

// TunnelRequest 隧道创建请求
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

// handleAPICreateTunnel 创建端口映射
// @Summary 创建端口映射
// @Description 为指定客户端创建端口映射隧道
// @Tags tunnel
// @Accept json
// @Produce json
// @Param request body server.TunnelRequest true "隧道创建请求"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/tunnels [post]
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

	// 获取客户端
	client, ok := s.clients.Get(req.ClientID)
	if !ok {
		c.JSON(http.StatusNotFound, map[string]string{"error": "client not found or offline"})
		return
	}

	// 分配公网端口
	publicPort, err := s.tunnelManager.AllocatePort()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "no available ports"})
		return
	}

	// 生成 tunnelID
	tunnelID := generateUUID()

	// 创建隧道
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

	// 启动端口监听
	if err := s.tunnelManager.Listen(publicPort, tunnelID); err != nil {
		s.tunnelManager.CloseTunnel(tunnelID)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// 通知 Agent 创建隧道
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

// handleAPIListTunnels 列出所有隧道
// @Summary 列出所有隧道
// @Description 获取所有隧道的列表
// @Tags tunnel
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/tunnels [get]
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

// handleAPIGetTunnel 获取隧道详情
// @Summary 获取隧道详情
// @Description 根据隧道ID获取隧道详细信息
// @Tags tunnel
// @Produce json
// @Param tunnel_id path string true "隧道ID"
// @Success 200 {object} Tunnel
// @Failure 404 {object} map[string]string
// @Router /api/tunnels/{tunnel_id} [get]
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

// handleAPIDeleteTunnel 删除端口映射
// @Summary 删除端口映射
// @Description 根据隧道ID删除端口映射
// @Tags tunnel
// @Produce json
// @Param tunnel_id path string true "隧道ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/tunnels/{tunnel_id} [delete]
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

	// 通知 Agent 关闭隧道
	tunnelClosePayload := common.TunnelClosePayload{
		TunnelID: tunnelID,
	}
	payloadJSON, _ := json.Marshal(tunnelClosePayload)
	tunnel.Client.WriteJSON(common.Message{
		Type:    "tunnel_close",
		Payload: payloadJSON,
	})

	// 关闭隧道
	if err := s.tunnelManager.CloseTunnel(tunnelID); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{"success": "true"})
}

// handleAPIListClientTunnels 获取指定客户端的隧道
// @Summary 获取指定客户端的隧道
// @Description 获取指定客户端的所有隧道
// @Tags tunnel
// @Produce json
// @Param client_id path string true "客户端ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/clients/{client_id}/tunnels [get]
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
