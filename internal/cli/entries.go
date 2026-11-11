package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/ptickz/rpwd/internal/clipboard"
	"github.com/ptickz/rpwd/internal/store"
	"github.com/ptickz/rpwd/internal/vault"
)

const maxDescWidth = 40

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

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid id %q", s)
	}

	return uint32(n), nil
}
