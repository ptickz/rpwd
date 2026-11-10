// Package cli implements rpwd subcommands.
package cli

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/ptickz/rpwd/internal/clipboard"
	"github.com/ptickz/rpwd/internal/crypto"
	"github.com/ptickz/rpwd/internal/store"
	"github.com/ptickz/rpwd/internal/vault"
)

const maxDescWidth = 40

var commands = []command{
	{name: "init", summary: "create a new vault", run: cmdInit},
	{name: "ls", summary: "list entries", run: cmdLs},
	{name: "show", summary: "<id> [--print]  show entry, copy password (--print: to stdout)", run: cmdShow},
	{name: "add", summary: "add an entry (interactive)", run: cmdAdd},
	{name: "edit", summary: "<id>  edit an entry, Enter keeps a value", run: cmdEdit},
	{name: "rm", summary: "<id>  delete an entry", run: cmdRm},
	{name: "passwd", summary: "change master password", run: cmdPasswd},
	{name: "dump", summary: "<dir> [--decrypt]  dump vault to dir (--decrypt: plain CSV)", run: cmdDump},
	// {name: "lock", summary: "lock vault for agent", run: cmdLock},
	// {name: "status", summary: "create a new vault", run: cmdStatus},
}

type command struct {
	name    string
	summary string
	run     func(a *app, args []string) error
}

func cmdInit(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	if _, err := os.Stat(a.vaultPath); err == nil {
		return store.ErrExists
	}

	password, err := a.readPassword("enter master password:")
	if err != nil {
		return err
	}
	defer clear(password)

	if utf8.RuneCount(password) < 12 {
		return errors.New("password too short, 12 char min")
	}

	repeatPassword, err := a.readPassword("repeat master password:")
	if err != nil {
		return err
	}
	defer clear(repeatPassword)

	if !bytes.Equal(password, repeatPassword) {
		return errors.New("passwords mismatch")
	}

	h, dek, err := crypto.New(password)
	if err != nil {
		return fmt.Errorf("key generate: %w", err)
	}
	defer clear(dek)

	var v vault.Vault

	payload, err := v.MarshalBinary()
	if err != nil {
		return fmt.Errorf("generating empty vault: %w", err)
	}

	buf, err := crypto.Seal(h, dek, payload)
	if err != nil {
		return fmt.Errorf("vault encrypting: %w", err)
	}

	err = store.Create(a.vaultPath, buf)
	if err != nil {
		return fmt.Errorf("storing new vault: %w", err)
	}

	_, _ = fmt.Fprintf(a.stderr, "vault created: %s\n", a.vaultPath)

	return nil
}

func cmdLs(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	dek, v, err := a.unlock()
	if err != nil {
		return err
	}
	defer clear(dek)

	entries := v.List()
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(a.stderr, "vault empty")
		return nil
	}

	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintln(tw, "ID\tTITLE\tLOGIN\tDESC")

	for _, e := range entries {
		_, _ = fmt.Fprintf(
			tw,
			"%d\t%s\t%s\t%s\n",
			e.ID, sanitize(e.Data.Title), sanitize(e.Data.Login), truncate(sanitize(e.Data.Desc), maxDescWidth),
		)
	}

	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}

		return r
	}, s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}

	return string(r[:n-1]) + "…"
}

func cmdShow(a *app, args []string) error {
	var (
		print bool
		rest  []string
	)

	for _, arg := range args {
		switch arg {
		case "--print":
			print = true
		default:
			rest = append(rest, arg)
		}
	}

	if len(rest) != 1 {
		return errors.New("usage: rpwd show <id> [--print]")
	}

	id, err := parseID(rest[0])
	if err != nil {
		return err
	}

	dek, v, err := a.unlock()
	if err != nil {
		return err
	}
	defer clear(dek)

	entry, err := v.Get(id)
	if err != nil {
		return err
	}

	if print {
		_, err := fmt.Fprintln(a.stdout, entry.Data.Password)
		if err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	} else {
		_, _ = fmt.Fprintf(a.stdout, "title: %s\nlogin: %s\ndesc:  %s\n",
			sanitize(entry.Data.Title), sanitize(entry.Data.Login), sanitize(entry.Data.Desc))

		err := clipboard.Copy([]byte(entry.Data.Password))
		if err != nil {
			return fmt.Errorf("%w (use --print)", err)
		}

		_, _ = fmt.Fprintln(a.stderr, "password copied to clipboard")
	}

	return nil
}

func cmdAdd(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	dek, _, err := a.unlock()
	if err != nil {
		return err
	}

	defer clear(dek)

	title, err := a.readLine("enter title: ")
	if err != nil {
		return err
	}

	desc, err := a.readLine("enter desc: ")
	if err != nil {
		return err
	}

	login, err := a.readLine("enter login: ")
	if err != nil {
		return err
	}

	password, err := a.readPassword("enter password:")
	if err != nil {
		return err
	}
	defer clear(password)

	passwordRepeat, err := a.readPassword("repeat password:")
	if err != nil {
		return err
	}
	defer clear(passwordRepeat)

	if !bytes.Equal(password, passwordRepeat) {
		return errors.New("passwords mismatch")
	}

	release, err := store.Lock(a.lockPath)
	if err != nil {
		return err
	}

	defer func() { _ = release() }()

	h, v, err := a.load(dek)
	if err != nil {
		return err
	}

	id, err := v.Add(vault.EntryData{
		Title:    title,
		Desc:     desc,
		Login:    login,
		Password: string(password),
	}, time.Now())
	if err != nil {
		return err
	}

	if err := a.save(h, dek, v); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(a.stdout, "entry added: %d\n", id)

	return nil
}

func cmdEdit(a *app, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: rpwd edit <id>")
	}

	id, err := parseID(args[0])
	if err != nil {
		return err
	}

	dek, v, err := a.unlock()
	if err != nil {
		return err
	}

	defer clear(dek)

	cur, err := v.Get(id)
	if err != nil {
		return err
	}

	title, err := a.readLine(fmt.Sprintf("title [%s]: ", sanitize(cur.Data.Title)))
	if err != nil {
		return err
	}

	desc, err := a.readLine(fmt.Sprintf("desc [%s]: ", sanitize(cur.Data.Desc)))
	if err != nil {
		return err
	}

	login, err := a.readLine(fmt.Sprintf("login [%s]: ", sanitize(cur.Data.Login)))
	if err != nil {
		return err
	}

	password, err := a.readPassword("enter password (enter to keep):")
	if err != nil {
		return err
	}
	defer clear(password)

	if len(password) > 0 {
		passwordRepeat, err := a.readPassword("repeat password:")
		if err != nil {
			return err
		}
		defer clear(passwordRepeat)

		if !bytes.Equal(password, passwordRepeat) {
			return errors.New("passwords mismatch")
		}
	}

	release, err := store.Lock(a.lockPath)
	if err != nil {
		return err
	}

	defer func() { _ = release() }()

	h, v, err := a.load(dek)
	if err != nil {
		return err
	}

	entry, err := v.Get(id)
	if err != nil {
		return err
	}

	if len(title) > 0 {
		entry.Data.Title = title
	}

	if len(desc) > 0 {
		entry.Data.Desc = desc
	}

	if len(login) > 0 {
		entry.Data.Login = login
	}

	if len(password) > 0 {
		entry.Data.Password = string(password)
	}

	_, err = v.Update(id, entry.Data, time.Now())
	if err != nil {
		return err
	}

	if err := a.save(h, dek, v); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(a.stdout, "entry updated: %d\n", id)

	return nil
}

func cmdRm(a *app, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: rpwd rm <id>")
	}

	id, err := parseID(args[0])
	if err != nil {
		return err
	}

	dek, v, err := a.unlock()
	if err != nil {
		return err
	}

	defer clear(dek)

	e, err := v.Get(id)
	if err != nil {
		return err
	}

	answer, err := a.readLine(fmt.Sprintf("delete %q? [y/N] ", sanitize(e.Data.Title)))
	if err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
	default:
		_, _ = fmt.Fprintln(a.stderr, "cancelled")

		return nil
	}

	release, err := store.Lock(a.lockPath)
	if err != nil {
		return err
	}

	defer func() { _ = release() }()

	h, v, err := a.load(dek)
	if err != nil {
		return err
	}

	err = v.Delete(id)
	if err != nil {
		return err
	}

	if err := a.save(h, dek, v); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(a.stdout, "entry deleted: %d\n", id)

	return nil
}

// func cmdLock(a *app, args []string) error {
// 	return errors.New("implement")
// }

// func cmdStatus(a *app, args []string) error {
// 	return errors.New("implement")
// }

func cmdPasswd(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	oldDEK, _, err := a.unlock()
	if err != nil {
		return err
	}
	defer clear(oldDEK)

	password, err := a.readPassword("new master password:")
	if err != nil {
		return err
	}
	defer clear(password)

	if utf8.RuneCount(password) < 12 {
		return errors.New("password too short, 12 char min")
	}

	repeatPassword, err := a.readPassword("repeat master password:")
	if err != nil {
		return err
	}
	defer clear(repeatPassword)

	if !bytes.Equal(password, repeatPassword) {
		return errors.New("passwords mismatch")
	}

	newHeader, newDEK, err := crypto.New(password)
	if err != nil {
		return fmt.Errorf("key generate: %w", err)
	}
	defer clear(newDEK)

	release, err := store.Lock(a.lockPath)
	if err != nil {
		return err
	}

	defer func() { _ = release() }()

	_, v, err := a.load(oldDEK)
	if err != nil {
		return err
	}

	err = a.save(newHeader, newDEK, v)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(a.stderr, "master password changed\nIMPORTANT: old backups will not work with new password")

	return nil
}

func cmdDump(a *app, args []string) error {
	if len(args) == 0 {
		return errors.New("provide save path")
	}

	if len(args) > 2 {
		return errors.New("redundant arguments")
	}

	path := ""
	decrypt := false

	for _, a := range args {
		if a == "--decrypt" {
			decrypt = true
		} else {
			if path != "" {
				return errors.New("provide only one save path")
			}

			i, err := os.Stat(a)
			if err != nil {
				return fmt.Errorf("opening provided path: %w", err)
			}

			if !i.IsDir() {
				return errors.New("provided path is not a directory")
			}

			path = a
		}
	}

	if path == "" {
		return errors.New("provide save path")
	}

	var data []byte

	ext := ".rpwd"

	if !decrypt {
		buf, warn, err := store.Read(a.vaultPath)
		if err != nil {
			return err
		}

		if warn {
			_, _ = fmt.Fprintf(a.stderr, "wrong permissions on: %s\n", a.vaultPath)
		}

		_, err = crypto.ParseHeader(buf)
		if err != nil {
			return err
		}

		data = buf
	} else {
		_, _ = fmt.Fprintln(a.stderr, "warning: passwords are stored in plain text, delete the file after use")

		dek, v, err := a.unlock()
		if err != nil {
			return err
		}
		defer clear(dek)

		var b bytes.Buffer

		w := csv.NewWriter(&b)

		_ = w.Write([]string{"title", "login", "password", "description"})

		for _, e := range v.List() {
			_ = w.Write([]string{e.Data.Title, e.Data.Login, e.Data.Password, e.Data.Desc})
		}

		w.Flush()

		if err := w.Error(); err != nil {
			return fmt.Errorf("build csv: %w", err)
		}

		data, ext = b.Bytes(), ".csv"
	}

	name := "rpwd-dump-" + time.Now().UTC().Format("20060102T150405.000Z") + ext

	err := store.WriteNewFile(filepath.Join(path, name), data)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(a.stdout, "dump written and can be found at: %s\n", filepath.Join(path, name))

	return nil
}

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

func (a *app) load(dek []byte) (*crypto.Header, *vault.Vault, error) {
	buf, warn, err := store.Read(a.vaultPath)
	if err != nil {
		return nil, nil, err
	}

	if warn {
		_, _ = fmt.Fprintf(a.stderr, "wrong permissions on: %s\n", a.vaultPath)
	}

	h, payload, err := crypto.Open(buf, dek)
	if err != nil {
		return nil, nil, err
	}
	defer clear(payload)

	var v vault.Vault

	err = v.UnmarshalBinary(payload)
	if err != nil {
		return nil, nil, err
	}

	return h, &v, nil
}

func (a *app) save(h *crypto.Header, dek []byte, v *vault.Vault) error {
	payload, err := v.MarshalBinary()
	if err != nil {
		return err
	}
	defer clear(payload)

	buf, err := crypto.Seal(h, dek, payload)
	if err != nil {
		return err
	}

	warn, err := store.Write(a.vaultPath, a.backupsDir, buf)
	if err != nil {
		return err
	}

	if warn != nil {
		_, _ = fmt.Fprintf(a.stderr, "rpwd: warning: %v\n", warn)
	}

	return nil
}

func (a *app) unlock() ([]byte, *vault.Vault, error) {
	buf, insecure, err := store.Read(a.vaultPath)
	if insecure {
		_, _ = fmt.Fprintf(a.stderr, "wrong permissions on: %s\n", a.vaultPath)
	}

	if err != nil {
		return nil, nil, err
	}

	h, err := crypto.ParseHeader(buf)
	if err != nil {
		return nil, nil, err
	}

	password, err := a.readPassword("enter master password:")
	if err != nil {
		return nil, nil, err
	}
	defer clear(password)

	dek, err := h.Unlock(password)
	if err != nil {
		return nil, nil, err
	}

	_, v, err := a.load(dek)
	if err != nil {
		clear(dek)

		return nil, nil, err
	}

	return dek, v, nil
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid id %q", s)
	}

	return uint32(n), nil
}
