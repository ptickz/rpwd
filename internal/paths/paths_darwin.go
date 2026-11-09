package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// 104 is trailing null.
const maxSocketPath = 103

func dataDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config dir: %w", err)
	}

	return filepath.Join(dir, "rpwd"), nil
}

func runtimeDir() string {
	return filepath.Join(os.TempDir(), "rpwd")
}
