package cli

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/ptickz/rpwd/internal/agent"
	"github.com/ptickz/rpwd/internal/crypto"
	"github.com/ptickz/rpwd/internal/store"
	"github.com/ptickz/rpwd/internal/vault"
)

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

func cmdPasswd(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	oldDEK, _, err := a.unlockWithPassword()
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

	_ = agent.Lock(a.socketPath)

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

		dek, v, err := a.unlockWithPassword()
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
