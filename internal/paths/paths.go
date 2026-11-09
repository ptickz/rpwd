// Package paths computes per-OS locations of the vault, backups, lock file and agent socket.
// It does not create anything.
package paths

import (
	"fmt"
	"path/filepath"
)

const (
	vaultName   = "vault.rpwd"
	lockName    = "vault.rpwd.lock"
	backupsName = "backups"
	socketName  = "agent.sock"
)

func VaultFile() (string, error) {
	return inDataDir(vaultName)
}

func BackupsDir() (string, error) {
	return inDataDir(backupsName)
}

func LockFile() (string, error) {
	return inDataDir(lockName)
}

func SocketFile() (string, error) {
	path := filepath.Join(runtimeDir(), socketName)
	if len(path) > maxSocketPath {
		return "", fmt.Errorf("socket path too long (%d > %d): %s", len(path), maxSocketPath, path)
	}

	return path, nil
}

func inDataDir(name string) (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, name), nil
}
