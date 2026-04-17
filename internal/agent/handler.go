package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"goremote/internal/common"
)

// Handler handles messages from server
type Handler struct {
	agent     *Agent
	uploads   map[string]*UploadTask // fileID -> UploadTask
	downloads map[string]*DownloadTask
	mu        sync.Mutex
}

// UploadTask represents an ongoing upload to server
type UploadTask struct {
	FileID   string
	Filename string
	File     *os.File
	Offset   int64
}

// DownloadTask represents an ongoing download from server
type DownloadTask struct {
	FileID   string
	Filename string
	File     *os.File
	Offset   int64
}

// NewHandler creates a new Handler
func NewHandler(agent *Agent) *Handler {
	return &Handler{
		agent:     agent,
		uploads:   make(map[string]*UploadTask),
		downloads: make(map[string]*DownloadTask),
	}
}

// Handle processes incoming messages
func (h *Handler) Handle(msg *common.Message) error {
	switch msg.Type {
	case "register_ok":
		return h.handleRegisterOK(msg)
	case "register_fail":
		return h.handleRegisterFail(msg)
	case "exec":
		return h.handleExec(msg)
	case "pong":
		return nil // heartbeat response, no action needed
	case "upload":
		return h.handleUpload(msg)
	case "upload_data":
		return h.handleUploadData(msg)
	case "upload_complete":
		return h.handleUploadComplete(msg)
	case "download_data":
		return h.handleDownloadData(msg)
	case "download_complete":
		return h.handleDownloadComplete(msg)
	case "download":
		return h.handleDownload(msg)
	case "tunnel_open":
		return h.handleTunnelOpen(msg)
	case "tunnel_open_ack":
		return h.handleTunnelOpenAck(msg)
	case "tunnel_close":
		return h.handleTunnelClose(msg)
	case "tunnel_data":
		return h.handleTunnelData(msg)
	case "tunnel_error":
		return h.handleTunnelError(msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// handleRegisterOK handles successful registration
func (h *Handler) handleRegisterOK(msg *common.Message) error {
	var payload common.RegisterOKPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	h.agent.SetClientID(payload.ClientID)
	slog.Info("registered successfully", "client_id", payload.ClientID)
	return nil
}

// handleRegisterFail handles failed registration
func (h *Handler) handleRegisterFail(msg *common.Message) error {
	var payload common.RegisterFailPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Error("registration failed", "reason", payload.Reason)
	return fmt.Errorf("registration failed: %s", payload.Reason)
}

// handleExec handles command execution request
func (h *Handler) handleExec(msg *common.Message) error {
	var payload common.ExecPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("executing command", "task_id", payload.TaskID, "command", payload.Command)

	result, err := h.agent.executor.Execute(payload.Command, payload.Timeout)
	if err != nil {
		slog.Warn("command execution error", "task_id", payload.TaskID, "error", err)
		result = &Result{
			ExitCode: -1,
			Stderr:   err.Error(),
		}
	}

	return h.agent.SendResult(payload.TaskID, result.ExitCode, result.Stdout, result.Stderr)
}

// handleUpload handles server upload request (server sending file to agent)
func (h *Handler) handleUpload(msg *common.Message) error {
	var payload common.UploadPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	// Ensure parent directory exists
	dir := filepath.Dir(payload.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return h.agent.SendUploadComplete(payload.FileID, false, err.Error())
	}

	// Create local file to receive data
	file, err := os.Create(payload.Filename)
	if err != nil {
		return h.agent.SendUploadComplete(payload.FileID, false, err.Error())
	}

	h.mu.Lock()
	h.downloads[payload.FileID] = &DownloadTask{
		FileID:   payload.FileID,
		Filename: payload.Filename,
		File:     file,
		Offset:   payload.Offset,
	}
	h.mu.Unlock()

	slog.Info("接收上传请求", "file_id", payload.FileID, "filename", payload.Filename)
	return nil
}

// handleUploadData handles file data from server
func (h *Handler) handleUploadData(msg *common.Message) error {
	var payload common.UploadDataPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	h.mu.Lock()
	task, ok := h.downloads[payload.FileID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown file_id: %s", payload.FileID)
	}

	// Decode data
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		task.File.Close()
		h.mu.Lock()
		delete(h.downloads, payload.FileID)
		h.mu.Unlock()
		return h.agent.SendUploadComplete(payload.FileID, false, err.Error())
	}

	// Write to file
	_, err = task.File.Write(data)
	if err != nil {
		task.File.Close()
		h.mu.Lock()
		delete(h.downloads, payload.FileID)
		h.mu.Unlock()
		return h.agent.SendUploadComplete(payload.FileID, false, err.Error())
	}

	task.Offset += int64(len(data))

	// Check if complete
	if payload.EOF {
		task.File.Close()
		h.mu.Lock()
		delete(h.downloads, payload.FileID)
		h.mu.Unlock()
		slog.Info("文件接收完成", "file_id", payload.FileID)
		return h.agent.SendUploadComplete(payload.FileID, true, "")
	}

	return nil
}

// handleUploadComplete handles upload completion response from server
func (h *Handler) handleUploadComplete(msg *common.Message) error {
	var payload common.UploadCompletePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	if !payload.Success {
		slog.Warn("upload failed", "file_id", payload.FileID, "error", payload.Error)
	} else {
		slog.Info("upload confirmed by server", "file_id", payload.FileID)
	}

	return nil
}

// handleDownload handles server request to download file from agent
func (h *Handler) handleDownload(msg *common.Message) error {
	var payload common.DownloadPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("download requested", "file_id", payload.FileID, "filename", payload.Filename)

	// Open file for reading
	file, err := os.Open(payload.Filename)
	if err != nil {
		h.agent.SendDownloadComplete(payload.FileID, false, err.Error())
		return err
	}

	stat, _ := file.Stat()

	h.mu.Lock()
	h.uploads[payload.FileID] = &UploadTask{
		FileID:   payload.FileID,
		Filename: payload.Filename,
		File:     file,
		Offset:   payload.Offset,
	}
	h.mu.Unlock()

	// Send file in chunks
	go h.sendFileData(payload.FileID, file, stat.Size())

	return nil
}

// sendFileData sends file data to server
func (h *Handler) sendFileData(fileID string, file *os.File, totalSize int64) {
	chunkSize := 64 * 1024 // 64KB
	buffer := make([]byte, chunkSize)
	offset := int64(0)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			data := base64.StdEncoding.EncodeToString(buffer[:n])
			eof := offset+int64(n) >= totalSize

			downloadDataPayload := common.DownloadDataPayload{
				FileID: fileID,
				Offset: offset,
				Data:   data,
				EOF:    eof,
			}
			payloadJSON, _ := json.Marshal(downloadDataPayload)
			err := h.agent.connector.Send(&common.Message{
				Type:    "download_data",
				Payload: payloadJSON,
			})
			if err != nil {
				slog.Error("failed to send download data", "file_id", fileID, "error", err)
				file.Close()
				h.mu.Lock()
				delete(h.uploads, fileID)
				h.mu.Unlock()
				return
			}
			offset += int64(n)
		}

		if err == io.EOF {
			file.Close()
			h.mu.Lock()
			delete(h.uploads, fileID)
			h.mu.Unlock()
			slog.Info("file sent for download", "file_id", fileID)
			return
		}
		if err != nil {
			slog.Error("failed to read file for download", "file_id", fileID, "error", err)
			file.Close()
			h.mu.Lock()
			delete(h.uploads, fileID)
			h.mu.Unlock()
			return
		}
	}
}

// handleDownloadData handles download data from server
func (h *Handler) handleDownloadData(msg *common.Message) error {
	var payload common.DownloadDataPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	h.mu.Lock()
	task, ok := h.downloads[payload.FileID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown file_id: %s", payload.FileID)
	}

	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return err
	}

	_, err = task.File.Write(data)
	if err != nil {
		task.File.Close()
		h.mu.Lock()
		delete(h.downloads, payload.FileID)
		h.mu.Unlock()
		return h.agent.SendDownloadComplete(payload.FileID, false, err.Error())
	}

	task.Offset += int64(len(data))

	if payload.EOF {
		task.File.Close()
		h.mu.Lock()
		delete(h.downloads, payload.FileID)
		h.mu.Unlock()
		return h.agent.SendDownloadComplete(payload.FileID, true, "")
	}

	return nil
}

// handleDownloadComplete handles download completion confirmation
func (h *Handler) handleDownloadComplete(msg *common.Message) error {
	var payload common.DownloadCompletePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	if !payload.Success {
		slog.Warn("download failed", "file_id", payload.FileID, "error", payload.Error)
	} else {
		slog.Info("download completed", "file_id", payload.FileID)
	}

	return nil
}

// uploadFile uploads a local file to the server
func (h *Handler) uploadFile(taskID, fileID, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, _ := file.Stat()
	chunkSize := 64 * 1024 // 64KB
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
			err := h.agent.connector.Send(&common.Message{
				Type:    "upload_data",
				Payload: payloadJSON,
			})
			if err != nil {
				return err
			}
			offset += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// handleTunnelOpen 处理隧道创建请求
func (h *Handler) handleTunnelOpen(msg *common.Message) error {
	var payload common.TunnelOpenPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("tunnel open request",
		"tunnel_id", payload.TunnelID,
		"local_addr", payload.LocalAddr,
		"local_port", payload.LocalPort,
		"protocol", payload.Protocol)

	// 创建隧道记录
	h.agent.tunnelManager.CreateTunnel(
		payload.TunnelID,
		payload.LocalAddr,
		payload.LocalPort,
		payload.Protocol,
		0, // publicPort 由服务端分配，ack 时会更新
	)

	return nil
}

// handleTunnelOpenAck 处理隧道创建确认
func (h *Handler) handleTunnelOpenAck(msg *common.Message) error {
	var payload common.TunnelOpenAckPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	if !payload.Success {
		slog.Warn("tunnel open failed",
			"tunnel_id", payload.TunnelID,
			"error", payload.Error)
		h.agent.tunnelManager.CloseTunnel(payload.TunnelID)
		return nil
	}

	// 更新隧道的公网端口
	tunnel, ok := h.agent.tunnelManager.GetTunnel(payload.TunnelID)
	if ok {
		tunnel.PublicPort = payload.PublicPort
	}

	slog.Info("tunnel open ack",
		"tunnel_id", payload.TunnelID,
		"public_port", payload.PublicPort)

	return nil
}

// handleTunnelClose 处理隧道关闭请求
func (h *Handler) handleTunnelClose(msg *common.Message) error {
	var payload common.TunnelClosePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Info("tunnel close request", "tunnel_id", payload.TunnelID)
	return h.agent.tunnelManager.CloseTunnel(payload.TunnelID)
}

// handleTunnelData 处理隧道数据
func (h *Handler) handleTunnelData(msg *common.Message) error {
	var payload common.TunnelDataPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	// 解码数据
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return err
	}

	// 获取或创建本地连接
	conn, err := h.agent.tunnelManager.GetOrCreateLocalConn(payload.ConnID, payload.TunnelID)
	if err != nil {
		h.agent.tunnelManager.SendError(payload.TunnelID, payload.ConnID, err.Error())
		return err
	}

	// 写入本地服务
	if _, err := conn.Write(data); err != nil {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
		h.agent.tunnelManager.SendError(payload.TunnelID, payload.ConnID, err.Error())
		return err
	}

	// 启动读取响应的 goroutine（如果还没有启动）
	h.agent.tunnelManager.StartReadLoop(payload.ConnID, payload.TunnelID)

	if payload.IsEOF {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
	}

	return nil
}

// handleTunnelError 处理隧道错误
func (h *Handler) handleTunnelError(msg *common.Message) error {
	var payload common.TunnelErrorPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	slog.Warn("tunnel error from server",
		"tunnel_id", payload.TunnelID,
		"conn_id", payload.ConnID,
		"error", payload.Error)

	// 关闭相关连接
	if payload.ConnID != "" {
		h.agent.tunnelManager.CloseLocalConn(payload.ConnID)
	}

	return nil
}
