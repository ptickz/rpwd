package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/ptickz/rpwd/internal/agent"
	"github.com/ptickz/rpwd/internal/crypto"
	"github.com/ptickz/rpwd/internal/settings"
	"github.com/ptickz/rpwd/internal/store"
	"github.com/ptickz/rpwd/internal/vault"
)

func cmdAgent(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	return agent.Serve(a.stdin, a.socketPath)
}

func cmdLock(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	err := agent.Lock(a.socketPath)
	if err != nil {
		if errors.Is(err, agent.ErrNoAgent) {
			_, _ = fmt.Fprintln(a.stdout, "already locked")

			return nil
		}
		return err
	}

	_, _ = fmt.Fprintln(a.stdout, "locked")

	return nil
}

func cmdStatus(a *app, args []string) error {
	if len(args) > 0 {
		return errors.New("redundant arguments")
	}

	expires, err := agent.Status(a.socketPath)
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		_, _ = fmt.Fprintln(a.stdout, "locked")
		return nil
	case err != nil:
		return err
	default:
		t := expires.Local().Format("15:04")
		left := int(time.Until(expires).Minutes())
		_, _ = fmt.Fprintf(a.stdout, "unlocked until %s (%dm left)\n", t, left)

		return nil
	}
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

func (a *app) unlockWithPassword() ([]byte, *vault.Vault, error) {
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

func (a *app) unlock() ([]byte, *vault.Vault, error) {
	if dek, v, ok := a.unlockFromAgent(); ok {
		return dek, v, nil
	}

	dek, v, err := a.unlockWithPassword()
	if err != nil {
		return nil, nil, err
	}

	if err := agent.Spawn(
		dek, 
		time.Now().Add(settings.SessionTTL), 
		a.socketPath,
	); err != nil {
		_, _ = fmt.Fprintf(a.stderr, "rpwd: warning: agent: %v\n", err)
	}

	return dek, v, nil
}

func (a *app) unlockFromAgent() ([]byte, *vault.Vault, bool) {
	dek, err := agent.GetKey(a.socketPath)
	if err != nil {
		if !errors.Is(err, agent.ErrNoAgent) {
			_, _ = fmt.Fprintf(a.stderr, "rpwd: warning: agent: %v\n", err)
		}

		return nil, nil, false
	}

	_, v, err := a.load(dek)
	if err != nil {
		clear(dek)

		if errors.Is(err, crypto.ErrWrongPassword) {
			_ = agent.Lock(a.socketPath)
		}

		return nil, nil, false
	}

	return dek, v, true
}
