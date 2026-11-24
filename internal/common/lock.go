package common

import (
	"errors"
	"fmt"
	"os"
)

// ErrLockBusy 表示锁文件已经被另一个进程（或本进程的另一处）持有。
var ErrLockBusy = errors.New("lock file is held by another process")

// FileLock 是操作系统级的建议锁。它和「创建时为独占」的锁文件有本质区别：
// 进程崩溃时内核会自动释放，所以残留的 .lock 文件不会造成假阳性——这也是
// 它能安全回答「服务还在跑吗」的唯一原因。
type FileLock struct {
	f *os.File
}

// TryLockFile 非阻塞地获取 path 上的排它锁；文件不存在时创建（0600）。
// 拿不到锁返回 ErrLockBusy，其余失败原样返回（权限、目录不存在等）。
func TryLockFile(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := tryLockFileDescriptor(f); err != nil {
		f.Close()
		return nil, err
	}
	return &FileLock{f: f}, nil
}

// ProbeLockFile 检查 path 上的锁是否被占用，但不创建文件、不产生任何副作用：
// 调用方在「只看不动」的场景（如备份恢复的 --dry-run）必须用它，否则光是
// 探测就会在数据目录里留下一个 .lock。
//
// 文件不存在 = 没有任何人持锁（锁必须先有文件才能加）。
func ProbeLockFile(path string) (held bool, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open lock file %s: %w", path, err)
	}
	defer f.Close()

	if err := tryLockFileDescriptor(f); err != nil {
		if errors.Is(err, ErrLockBusy) {
			return true, nil
		}
		return false, err
	}
	// 探测成功说明没被占用，立刻放掉，别把锁带走。
	_ = unlockFileDescriptor(f)
	return false, nil
}

// Release 释放锁并关闭文件；重复调用安全。
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	if err := unlockFileDescriptor(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
