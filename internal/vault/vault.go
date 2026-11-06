package vault

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
	"unicode/utf8"
)

type Vault struct {
	nextID  uint32
	entries []Entry
}

type Entry struct {
	ID        uint32
	CreatedAt time.Time
	UpdatedAt time.Time
	Data      EntryData
}

type EntryData struct {
	Title    string
	Desc     string
	Login    string
	Password string
}

type ValidationError struct {
	Field  string
	Reason string
}

var (
	ErrNotFound     = errors.New("entry not found")
	ErrIDsExhausted = errors.New("hit entry ids limit")
)

const (
	MaxTitleLoginLen = 256
	MaxDescLen       = 4096
	MaxPasswrodLen   = 1024
)

func (v *Vault) Add(d EntryData, now time.Time) (uint32, error) {
	err := d.validateInput()
	if err != nil {
		return 0, err
	}

	if v.nextID == 0 {
		v.nextID = 1
	}

	if v.nextID == math.MaxUint32 {
		return 0, ErrIDsExhausted
	}

	now = now.UTC().Truncate(time.Second)

	id := v.nextID
	v.entries = append(v.entries, Entry{
		ID:        id,
		CreatedAt: now,
		UpdatedAt: now,
		Data:      d,
	})
	v.nextID++

	return id, nil
}

func (v *Vault) Update(id uint32, d EntryData, now time.Time) (Entry, error) {
	if err := d.validateInput(); err != nil {
		return Entry{}, err
	}

	i, err := v.index(id)
	if err != nil {
		return Entry{}, err
	}

	v.entries[i].Data = d
	v.entries[i].UpdatedAt = now.UTC().Truncate(time.Second)

	return v.entries[i], nil
}

func (v *Vault) Delete(id uint32) error {
	i, err := v.index(id)
	if err != nil {
		return err
	}

	v.entries = slices.Delete(v.entries, i, i+1)

	return nil
}

func (v *Vault) List() []Entry {
	return slices.Clone(v.entries)
}

func (v *Vault) Get(id uint32) (Entry, error) {
	i, err := v.index(id)
	if err != nil {
		return Entry{}, err
	}

	return v.entries[i], nil
}

func (d EntryData) validateInput() error {
	fields := []struct {
		name     string
		value    string
		required bool
		maxLen   int
	}{
		{"title", d.Title, true, MaxTitleLoginLen},
		{"desc", d.Desc, false, MaxDescLen},
		{"login", d.Login, true, MaxTitleLoginLen},
		{"password", d.Password, true, MaxPasswrodLen},
	}

	for _, f := range fields {
		switch {
		case f.required && f.value == "":
			return &ValidationError{Field: f.name, Reason: "must not be empty"}
		case len(f.value) > f.maxLen:
			return &ValidationError{Field: f.name, Reason: fmt.Sprintf("longer than %d bytes", f.maxLen)}
		case !utf8.ValidString(f.value):
			return &ValidationError{Field: f.name, Reason: "not valid UTF-8"}
		}
	}

	return nil
}

func (v *Vault) index(id uint32) (int, error) {
	i := slices.IndexFunc(v.entries, func(e Entry) bool { return e.ID == id })

	if i < 0 {
		return 0, fmt.Errorf("entry %d: %w", id, ErrNotFound)
	}

	return i, nil
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Reason)
}
