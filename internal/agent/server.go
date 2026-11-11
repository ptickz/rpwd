// Package agent keeps the vault key in memory for one session, so the master
// password is asked once per hour instead of on every command.
package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type server struct {
	mu         sync.Mutex
	closed     bool
	dek        []byte
	deadline   time.Time
	ln         net.Listener
	socketPath string
}

func Serve(in io.Reader, socketPath string) error {
	buf, err := io.ReadAll(io.LimitReader(in, 41))
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	defer clear(buf)

	if len(buf) != 40 {
		return fmt.Errorf("bad key payload: %d bytes", len(buf))
	}

	deadline := time.Unix(int64(binary.BigEndian.Uint64(buf[:8])), 0)

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("agent listen: %w", err)
	}

	s := server{
		dek:        buf[8:],
		deadline:   deadline,
		ln:         l,
		socketPath: socketPath,
	}

	time.AfterFunc(time.Until(deadline), func() { _ = s.shutdown() })

	var wg sync.WaitGroup

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			break
		}

		wg.Go(func() { s.handle(conn) })
	}

	wg.Wait()

	return nil
}

func (s *server) handle(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(time.Second))

	var req request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	s.mu.Lock()
	expired := s.closed || !time.Now().Round(0).Before(s.deadline)

	var key []byte
	if !expired && req.Op == opGetKey {
		key = bytes.Clone(s.dek)
	}
	s.mu.Unlock()

	if expired {
		_ = json.NewEncoder(conn).Encode(response{Error: "expired"})

		_ = s.shutdown()

		return
	}

	var resp response

	switch req.Op {
	case opGetKey:
		resp.Key = key
	case opStatus:
		resp.ExpiresAt = s.deadline
	case opLock:
		if err := s.shutdown(); err != nil {
			resp.Error = err.Error()
		}
	default:
		resp.Error = "unknown op"
	}

	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *server) shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	clear(s.dek)

	s.closed = true
	err := s.ln.Close()

	if rmErr := os.Remove(s.socketPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		err = errors.Join(err, rmErr)
	}

	return err
}
