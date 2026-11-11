package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func (a *app) readPassword(prompt string) ([]byte, error) {
	f, ok := a.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		line, err := a.readLine(prompt)
		return []byte(line), err
	}

	fd := int(f.Fd())

	stop, err := a.restoreOnInterrupt(fd)
	if err != nil {
		return nil, err
	}
	defer stop()

	_, _ = fmt.Fprint(a.stderr, prompt)
	pass, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(a.stderr)

	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	return pass, nil
}

func (a *app) restoreOnInterrupt(fd int) (stop func(), err error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("get terminal state: %w", err)
	}

	sig := make(chan os.Signal, 1)
	done := make(chan struct{})

	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case <-sig:
			_ = term.Restore(fd, state)
			_, _ = fmt.Fprintln(a.stderr)

			os.Exit(130)
		case <-done:
		}
	}()

	return func() {
		signal.Stop(sig)
		close(done)
	}, nil
}

func (a *app) readLine(prompt string) (string, error) {
	_, _ = fmt.Fprint(a.stderr, prompt)

	line, err := a.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", fmt.Errorf("read input: %w", err)
	}

	return strings.TrimRight(line, "\r\n"), nil
}
