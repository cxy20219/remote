package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	DefaultLogMaxSizeMB = 50
	DefaultLogBackups   = 5
)

type RotatingFileWriter struct {
	mu           sync.Mutex
	path         string
	maxSizeBytes int64
	maxBackups   int
	file         *os.File
	size         int64
}

func NewRotatingFileWriter(path string, maxSizeMB, maxBackups int) (*RotatingFileWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("log file path is required")
	}
	if maxSizeMB <= 0 {
		maxSizeMB = DefaultLogMaxSizeMB
	}
	if maxBackups <= 0 {
		maxBackups = DefaultLogBackups
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	var size int64
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}

	return &RotatingFileWriter{
		path:         path,
		maxSizeBytes: int64(maxSizeMB) * 1024 * 1024,
		maxBackups:   maxBackups,
		file:         f,
		size:         size,
	}, nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, fmt.Errorf("log file is closed")
	}

	if w.size > 0 && w.size+int64(len(p)) > w.maxSizeBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotatingFileWriter) rotateLocked() error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
	}

	if w.maxBackups > 0 {
		_ = os.Remove(w.backupPath(w.maxBackups))
		for i := w.maxBackups - 1; i >= 1; i-- {
			src := w.backupPath(i)
			dst := w.backupPath(i + 1)
			if _, err := os.Stat(src); err == nil {
				_ = os.Remove(dst)
				if err := os.Rename(src, dst); err != nil {
					return err
				}
			}
		}
		if _, err := os.Stat(w.path); err == nil {
			if err := w.rotateCurrentToFirstBackupLocked(); err != nil {
				return err
			}
		}
	} else {
		_ = os.Remove(w.path)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

func (w *RotatingFileWriter) backupPath(index int) string {
	return fmt.Sprintf("%s.%d", w.path, index)
}

func (w *RotatingFileWriter) rotateCurrentToFirstBackupLocked() error {
	backup := w.backupPath(1)
	_ = os.Remove(backup)

	st, err := os.Stat(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if st.Size() <= w.maxSizeBytes {
		return os.Rename(w.path, backup)
	}

	if err := copyFileTail(w.path, backup, w.maxSizeBytes); err != nil {
		_ = os.Remove(backup)
		_ = os.Remove(w.path)
		return nil
	}
	return os.Remove(w.path)
}

func copyFileTail(src, dst string, limit int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return err
	}

	offset := st.Size() - limit
	if offset < 0 {
		offset = 0
	}
	if _, err := in.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
