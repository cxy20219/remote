package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"goremote/internal/common"
)

// API handlers

func (s *Server) handleAPIClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		clients := s.clients.List()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"clients": clients,
			"total":   len(clients),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIClientDetail(w http.ResponseWriter, r *http.Request) {
	// Extract client ID from path: /api/clients/:id
	path := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	clientID := strings.TrimSuffix(path, "/")

	client, ok := s.clients.Get(clientID)
	if !ok {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

func (s *Server) handleAPIExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		Command  string `json:"command"`
		Timeout  int    `json:"timeout"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.Command == "" {
		http.Error(w, "client_id and command are required", http.StatusBadRequest)
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
		http.Error(w, "client not found or offline", http.StatusNotFound)
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
		slog.Error("failed to send command", "error", err)
		http.Error(w, "failed to send command", http.StatusInternalServerError)
		return
	}

	s.tasks.Update(taskID, StatusRunning)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"task_id": taskID,
		"status":  "pending",
	})
}

func (s *Server) handleAPITasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tasks := s.tasks.List()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tasks": tasks,
			"total": len(tasks),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPITaskDetail(w http.ResponseWriter, r *http.Request) {
	// Extract task ID from path: /api/tasks/:id
	path := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	taskID := strings.TrimSuffix(path, "/")

	task := s.tasks.Get(taskID)
	if task == nil {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}
