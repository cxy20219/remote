//go:build !windows

package common

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFileDescriptor 用 flock(LOCK_EX|LOCK_NB) 取排它锁。flock 的锁挂在
// 打开文件描述上，同一进程另开一次描述去抢同一文件也会失败——所以「服务在跑
// 时 restore 被拒」这件事在单进程内也能被测出来。
func tryLockFileDescriptor(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrLockBusy
	}
	return err
}

func unlockFileDescriptor(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
