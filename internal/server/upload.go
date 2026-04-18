package server

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// UploadFile represents an ongoing file upload
type UploadFile struct {
	FileID      string
	Filename    string
	Size        int64
	Offset      int64
	Transferred int64
	File        *os.File
	TaskID      string
	ClientID    string
	Status      string // in_progress/completed/failed
	CreatedAt   time.Time
	IsDownload  bool // true if this is a download (server receiving from client)
}

// UploadManager manages ongoing file uploads
type UploadManager struct {
	mu    sync.Mutex
	files map[string]*UploadFile // fileID -> UploadFile
}

// NewUploadManager creates a new UploadManager
func NewUploadManager() *UploadManager {
	return &UploadManager{
		files: make(map[string]*UploadFile),
	}
}

// Add adds a new upload
// If isDownload is true, the file is not created here (server will write to it later)
func (m *UploadManager) Add(upload *UploadFile, isDownload bool) error {
	if !isDownload {
		if err := os.MkdirAll(filepath.Dir(upload.Filename), 0755); err != nil {
			return err
		}

		// Create file for writing (upload mode: server sends file to client)
		file, err := os.Create(upload.Filename)
		if err != nil {
			return err
		}
		upload.File = file
	}

	upload.Status = "in_progress"
	upload.CreatedAt = time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[upload.FileID] = upload
	return nil
}

// Get retrieves an upload by file ID
func (m *UploadManager) Get(fileID string) *UploadFile {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.files[fileID]
}

// Remove removes an upload
func (m *UploadManager) Remove(fileID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if upload, ok := m.files[fileID]; ok && upload.File != nil {
		upload.File.Close()
	}
	delete(m.files, fileID)
}
