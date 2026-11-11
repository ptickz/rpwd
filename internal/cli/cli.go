package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/ptickz/rpwd/internal/crypto"
	"github.com/ptickz/rpwd/internal/paths"
	"github.com/ptickz/rpwd/internal/store"
	"github.com/ptickz/rpwd/internal/vault"
)

type app struct {
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	in         *bufio.Reader
	vaultPath  string
	backupsDir string
	lockPath   string
	socketPath string
}

func newApp(stdin io.Reader, stdout, stderr io.Writer) (*app, error) {
	vaultPath, err := paths.VaultFile()
	if err != nil {
		return nil, fmt.Errorf("vault path: %w", err)
	}

	backupsDir, err := paths.BackupsDir()
	if err != nil {
		return nil, fmt.Errorf("backups path: %w", err)
	}

	lockPath, err := paths.LockFile()
	if err != nil {
		return nil, fmt.Errorf("lock path: %w", err)
	}

	socketPath, err := paths.SocketFile()
	if err != nil {
		return nil, fmt.Errorf("socket path: %w", err)
	}

	return &app{
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		in:         bufio.NewReader(stdin),
		vaultPath:  vaultPath,
		backupsDir: backupsDir,
		lockPath:   lockPath,
		socketPath: socketPath,
	}, nil
}

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a, err := newApp(stdin, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rpwd: %v\n", err)

		return 1
	}

	if len(args) == 0 {
		a.errorf("no command given, for command list try --help")

		return 1
	}

	if slices.Contains([]string{"help", "-h", "--help"}, args[0]) {
		if err := a.printUsage(); err != nil {
			a.errorf("%v", err)

			return 1
		}

		return 0
	}

	i := slices.IndexFunc(commands, func(c command) bool { return c.name == args[0] })
	if i < 0 {
		a.errorf("unknown command %q", args[0])

		return 1
	}

	cmd := commands[i]

	err = cmd.run(a, args[1:])
	if err != nil {
		a.errorf("%v", err)
	}

	return exitCode(err)
}

func (a *app) printUsage() error {
	w := bufio.NewWriter(a.stdout)

	_, _ = fmt.Fprintln(w, "Available commands:")

	for _, c := range commands {
		if c.hidden {
			continue
		}

		_, _ = fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("write usage: %w", err)
	}

	return nil
}

func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, crypto.ErrWrongPassword):
		return 2
	case errors.Is(err, vault.ErrNotFound):
		return 3
	case errors.Is(err, store.ErrNotInitialized):
		return 4
	default:
		return 1
	}
}

func (a *app) errorf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.stderr, "rpwd: "+format+"\n", args...)
}
