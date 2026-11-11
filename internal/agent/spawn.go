package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func Spawn(dek []byte, deadline time.Time, socketPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("exe path name: %w", err)
	}

	cmd := exec.Command(exe, "__agent")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	w, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("agent start: %w", err)
	}

	buf := binary.BigEndian.AppendUint64(nil, uint64(deadline.Unix()))

	buf = append(buf, dek...)
	defer clear(buf)

	if _, err = w.Write(buf); err != nil {
		_ = w.Close()
		_ = cmd.Process.Kill()

		return fmt.Errorf("write to agent: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("pipe close: %w", err)
	}

	for range 20 {
		if _, err := Status(socketPath); err == nil {
			return nil
		}

		time.Sleep(50 * time.Millisecond)
	}

	return errors.New("agent did not start")
}
