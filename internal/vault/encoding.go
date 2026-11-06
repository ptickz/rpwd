package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	payloadV1 uint16 = 1

	payloadVersion = payloadV1
	minEntrySize   = 36
)

var ErrUnsupportedVersion = errors.New("unsupported payload version")
var ErrCorrupted = errors.New("corrupted vault data")

type reader struct {
	data []byte
	off  int
	err  error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}

	if n < 0 || n > len(r.data)-r.off {
		r.err = ErrCorrupted
		return nil
	}

	b := r.data[r.off : r.off+n]
	r.off += n

	return b
}

func (r *reader) uint16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}

	return binary.BigEndian.Uint16(b)
}

func (r *reader) uint32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}

	return binary.BigEndian.Uint32(b)
}

func (r *reader) uint64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}

	return binary.BigEndian.Uint64(b)
}

func (r *reader) string() string {
	n := r.uint32()
	return string(r.take(int(n)))
}

func (r *reader) time() time.Time {
	n := r.uint64()

	return time.Unix(int64(n), 0).UTC()
}

func (v *Vault) UnmarshalBinary(data []byte) error {
	r := &reader{data: data}

	ver := r.uint16()
	if r.err != nil {
		return r.err
	}

	var (
		nextID  uint32
		entries []Entry
		err     error
	)

	switch ver {
	case payloadV1:
		nextID, entries, err = r.processPayloadV1()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("payload version %d: %w", ver, ErrUnsupportedVersion)
	}

	v.nextID = nextID
	v.entries = entries

	return nil
}

func (v *Vault) MarshalBinary() ([]byte, error) {
	var res []byte

	res = binary.BigEndian.AppendUint16(res, payloadVersion)
	res = binary.BigEndian.AppendUint32(res, v.nextID)

	res = binary.BigEndian.AppendUint32(res, uint32(len(v.entries)))
	for _, e := range v.entries {
		res = binary.BigEndian.AppendUint32(res, e.ID)
		res = binary.BigEndian.AppendUint64(res, uint64(e.CreatedAt.Unix()))
		res = binary.BigEndian.AppendUint64(res, uint64(e.UpdatedAt.Unix()))
		res = appendString(res, e.Data.Title)
		res = appendString(res, e.Data.Desc)
		res = appendString(res, e.Data.Login)
		res = appendString(res, e.Data.Password)
	}

	return res, nil
}

func appendString(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	buf = append(buf, s...)

	return buf
}

func (r *reader) processPayloadV1() (uint32, []Entry, error) {
	nextID := r.uint32()

	count := r.uint32()
	if r.err != nil {
		return 0, nil, r.err
	}

	if uint64(count) > uint64(len(r.data)-r.off)/minEntrySize {
		return 0, nil, ErrCorrupted
	}

	entries := make([]Entry, 0, count)

	var lastID uint32

	for range count {
		id := r.uint32()
		if id == 0 || id <= lastID || id >= nextID {
			return 0, nil, ErrCorrupted
		}

		created := r.time()
		updated := r.time()
		title := r.string()
		desc := r.string()
		login := r.string()

		password := r.string()
		if r.err != nil {
			return 0, nil, r.err
		}

		d := EntryData{
			Title:    title,
			Desc:     desc,
			Login:    login,
			Password: password,
		}

		err := d.validateInput()
		if err != nil {
			return 0, nil, fmt.Errorf("%w: entry %d: %w", ErrCorrupted, id, err)
		}

		entries = append(entries, Entry{
			ID:        id,
			CreatedAt: created,
			UpdatedAt: updated,
			Data:      d,
		})

		lastID = id
	}

	if r.off != len(r.data) {
		return 0, nil, ErrCorrupted
	}

	return nextID, entries, nil
}
