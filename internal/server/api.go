package server

import (
	"encoding/json"
	"io"
	"net/http"

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
	err = client.Conn.WriteJSON(common.Message{
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
