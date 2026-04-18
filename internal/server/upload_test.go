package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUploadManagerAddCreatesParentDirectories(t *testing.T) {
	manager := NewUploadManager()
	target := filepath.Join(t.TempDir(), "nested", "dir", "payload.bin")

	upload := &UploadFile{
		FileID:   "file-1",
		Filename: target,
	}

	if err := manager.Add(upload, false); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	defer manager.Remove(upload.FileID)

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected upload file to exist: %v", err)
	}
	if upload.File == nil {
		t.Fatal("expected Add to open the upload file")
	}
}

func TestUploadManagerRemoveClosesOpenFile(t *testing.T) {
	manager := NewUploadManager()
	target := filepath.Join(t.TempDir(), "payload.bin")

	upload := &UploadFile{
		FileID:   "file-2",
		Filename: target,
	}

	if err := manager.Add(upload, false); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	manager.Remove(upload.FileID)

	if got := manager.Get(upload.FileID); got != nil {
		t.Fatal("expected upload to be removed from manager")
	}

	if err := os.Remove(target); err != nil {
		t.Fatalf("expected file to be removable after Remove closed it: %v", err)
	}
}
