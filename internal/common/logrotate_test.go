package common

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFileWriterRotatesAndCapsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")

	w, err := NewRotatingFileWriter(path, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter failed: %v", err)
	}
	w.maxSizeBytes = 20
	defer w.Close()

	for i := 0; i < 5; i++ {
		if _, err := fmt.Fprintf(w, "line-%02d-abcdef\n", i); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current log missing: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("first backup missing: %v", err)
	}
	if _, err := os.Stat(path + ".2"); err != nil {
		t.Fatalf("second backup missing: %v", err)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("unexpected backup beyond cap: %v", err)
	}
}

func TestRotatingFileWriterCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "app.log")
	w, err := NewRotatingFileWriter(path, 1, 1)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter failed: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log file missing: %v", err)
	}
}

func TestRotatingFileWriterCapsOversizedExistingLogBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("0123456789abcdefghijklmnopqrstuvwxyz"), 0644); err != nil {
		t.Fatalf("seed log failed: %v", err)
	}

	w, err := NewRotatingFileWriter(path, 1, 1)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter failed: %v", err)
	}
	w.maxSizeBytes = 10
	defer w.Close()

	if _, err := w.Write([]byte("next\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	st, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if st.Size() > 10 {
		t.Fatalf("backup should be capped to max size, got %d", st.Size())
	}
}
