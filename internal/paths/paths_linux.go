package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

const maxSocketPath = 108

func dataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}

	return filepath.Join(home, ".local", "share", "rpwd"), nil
}

func runtimeDir() string {
	path := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "rpwd")
	if !filepath.IsAbs(path) {
		path = filepath.Join(os.TempDir(), fmt.Sprintf("rpwd-%d", os.Getuid()))
	}

	return path
}
