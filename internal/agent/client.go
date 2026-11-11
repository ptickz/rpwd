package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"
)

var ErrNoAgent = errors.New("agent not running")

func call(socketPath string, req request) (response, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return response{}, ErrNoAgent
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			if err := os.Remove(socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return response{}, fmt.Errorf("drop socket: %w", err)
			}
			return response{}, ErrNoAgent
		} else {
			return response{}, fmt.Errorf("socket dial: %w", err)
		}
	}

	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(time.Second))

	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return response{}, fmt.Errorf("request encode: %w", err)
	}

	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return response{}, fmt.Errorf("response decode: %w", err)
	}

	if len(resp.Error) > 0 {
		if resp.Error == "expired" {
			return response{}, ErrNoAgent
		} else {
			return response{}, fmt.Errorf("agent: %s", resp.Error)
		}
	}

	return resp, nil
}

func GetKey(socketPath string) ([]byte, error) {
	resp, err := call(socketPath, request{
		Op: opGetKey,
	})
	if err != nil {
		return nil, err
	}

	return resp.Key, nil
}

func Status(socketPath string) (time.Time, error) {
	resp, err := call(socketPath, request{
		Op: opStatus,
	})
	if err != nil {
		return time.Time{}, err
	}

	return resp.ExpiresAt, nil
}

func Lock(socketPath string) error {
	_, err := call(socketPath, request{Op: opLock})
	return err
}
