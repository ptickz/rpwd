package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func New(password []byte) (*Header, []byte, error) {
	h := &Header{params: defaultParams}
	rand.Read(h.salt[:])
	rand.Read(h.nonceDEK[:])

	dek := make([]byte, keySize)
	rand.Read(dek)

	kek := deriveKEK(password, h.salt[:], h.params)

	defer clear(kek)

	if err := wrapDEK(h, kek, dek); err != nil {
		clear(dek)
		return nil, nil, err
	}

	return h, dek, nil
}

func wrapDEK(h *Header, kek, dek []byte) error {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return fmt.Errorf("init aead: %w", err)
	}

	aad := h.marshal()[:dekAADEnd]
	sealed := aead.Seal(nil, h.nonceDEK[:], dek, aad)
	copy(h.encDEK[:], sealed)

	return nil
}

func (h *Header) Unlock(password []byte) ([]byte, error) {
	kek := deriveKEK(password, h.salt[:], h.params)
	defer clear(kek)

	dek, err := unwrapDEK(h, kek)
	if err != nil {
		return nil, err
	}

	return dek, nil
}

func unwrapDEK(h *Header, kek []byte) ([]byte, error) {
	aad := h.marshal()[:dekAADEnd]

	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("init aead: %w", err)
	}

	dek, err := aead.Open(nil, h.nonceDEK[:], h.encDEK[:], aad)
	if err != nil {
		return nil, ErrWrongPassword
	}

	return dek, nil
}

func Open(file, dek []byte) (*Header, []byte, error) {
	h, err := ParseHeader(file)
	if err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("init aead: %w", err)
	}

	payload, err := aead.Open(nil, h.nonceData[:], file[headerSize:], file[:headerSize])
	if err != nil {
		return nil, nil, ErrCorrupted
	}

	return h, payload, nil
}

func Seal(h *Header, dek, payload []byte) ([]byte, error) {
	hc := *h
	rand.Read(hc.nonceData[:])
	hdr := hc.marshal()

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("init aead: %w", err)
	}

	dst := make([]byte, 0, headerSize+len(payload)+tagSize)
	dst = append(dst, hdr...)

	out := aead.Seal(dst, hc.nonceData[:], payload, hdr)

	return out, nil
}

func deriveKEK(password, salt []byte, p Params) []byte {
	return argon2.IDKey(
		password,
		salt,
		p.Time,
		p.Memory,
		p.Threads,
		keySize,
	)
}
