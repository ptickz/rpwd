//go:build unix

package store

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func Lock(lockPath string) (unlock func() error, err error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock vault: %w", err)
	}

	return f.Close, nil
}
