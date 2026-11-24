//go:build windows

package common

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows 没有 flock，用 LockFileEx 独占字节 0 上的 1 个字节达到同样效果：
// 同样是内核对象，进程退出即释放。生产部署在 Linux，这里只需要保证
// GOOS=windows 能编译、语义不退化。
func tryLockFileDescriptor(f *os.File) error {
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped),
	)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLockBusy
	}
	return err
}

func unlockFileDescriptor(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
