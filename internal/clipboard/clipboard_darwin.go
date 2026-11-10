package clipboard

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

func Copy(b []byte) error {
	cmd := exec.Command("/usr/bin/pbcopy")

	cmd.Env = append(os.Environ(), "LC_CTYPE=UTF-8")
	cmd.Stdin = bytes.NewReader(b)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pbcopy: %w", err)
	}

	return nil
}

func Read() ([]byte, error) {
	cmd := exec.Command("/usr/bin/pbpaste")

	cmd.Env = append(os.Environ(), "LC_CTYPE=UTF-8")

	buf, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read output: %w", err)
	}

	return buf, nil
}

func Clear() error {
	return Copy(nil)
}
