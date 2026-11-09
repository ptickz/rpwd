// Package store reads and atomically writes the vault file, keeps backups and locks the vault.
// It works with raw bytes and knows nothing about encryption.
package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ptickz/rpwd/internal/settings"
)

var (
	ErrNotInitialized = errors.New("vault not initialized")
	ErrExists         = errors.New("vault already exists")
)

func Read(path string) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, ErrNotInitialized
		}

		return nil, false, fmt.Errorf("open vault: %w", err)
	}

	defer func() { _ = f.Close() }()

	insecure, err := insecurePerm(f)
	if err != nil {
		return nil, false, err
	}

	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, insecure, fmt.Errorf("read vault: %w", err)
	}

	return buf, insecure, nil
}

func Create(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}

		return fmt.Errorf("create vault: %w", err)
	}

	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("write vault: %w", err)
	}

	err = f.Sync()
	if err != nil {
		return fmt.Errorf("sync vault: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("close vault: %w", err)
	}

	ok = true

	return nil
}

func Write(path, backupsDir string, data []byte) (error, error) {
	var warn error

	tmp, err := os.CreateTemp(filepath.Dir(path), "vault-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}

	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	if _, err = tmp.Write(data); err != nil {
		return nil, fmt.Errorf("write temp: %w", err)
	}

	err = tmp.Sync()
	if err != nil {
		return nil, fmt.Errorf("sync temp: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return nil, fmt.Errorf("close temp: %w", err)
	}

	if err := backup(path, backupsDir); err != nil {
		if errors.Is(err, ErrNotInitialized) {
			return nil, err
		}

		warn = fmt.Errorf("backup: %w", err)
	}

	err = os.Rename(tmp.Name(), path)
	if err != nil {
		return nil, fmt.Errorf("rename temp: %w", err)
	}

	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.Join(warn, fmt.Errorf("vault saved, but open dir failed: %w", err)), nil
	}

	defer func() {
		_ = dir.Close()
	}()

	if err := dir.Sync(); err != nil {
		return errors.Join(warn, fmt.Errorf("vault saved, but sync dir failed: %w", err)), nil
	}

	return warn, nil
}

func insecurePerm(f *os.File) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("stat vault: %w", err)
	}

	return info.Mode().Perm()&0o077 != 0, nil
}

func backup(path, backupsDir string) error {
	err := os.MkdirAll(backupsDir, 0o700)
	if err != nil {
		return fmt.Errorf("create backups dir: %w", err)
	}

	buf, _, err := Read(path)
	if err != nil {
		return err
	}

	name := "vault-" + time.Now().UTC().Format("20060102T150405.000Z") + ".rpwd"

	bac, err := os.OpenFile(filepath.Join(backupsDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}

	ok := false
	defer func() {
		if !ok {
			_ = bac.Close()
			_ = os.Remove(bac.Name())
		}
	}()

	if _, err = bac.Write(buf); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}

	err = bac.Sync()
	if err != nil {
		return fmt.Errorf("sync backup: %w", err)
	}

	err = bac.Close()
	if err != nil {
		return fmt.Errorf("close backup: %w", err)
	}

	ok = true

	entries, err := os.ReadDir(backupsDir)
	if err != nil {
		return fmt.Errorf("read backups dir: %w", err)
	}

	var backups []fs.DirEntry

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "vault-") || !strings.HasSuffix(name, ".rpwd") {
			continue
		}

		backups = append(backups, e)
	}

	excess := len(backups) - settings.BackupsKeep
	for _, e := range backups[:max(excess, 0)] {
		err := os.Remove(filepath.Join(backupsDir, e.Name()))
		if err != nil {
			return fmt.Errorf("delete old backup: %w", err)
		}
	}

	return nil
}
