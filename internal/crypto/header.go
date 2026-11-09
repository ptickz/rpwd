package crypto

import (
	"encoding/binary"
)

// Header is the fixed-size, unencrypted start of a vault file.
// It holds the KDF parameters and the wrapped DEK.
type Header struct {
	params    Params
	salt      [saltSize]byte
	nonceDEK  [nonceSize]byte
	encDEK    [encDEKSize]byte
	nonceData [nonceSize]byte
}

func (h *Header) marshal() []byte {
	buf := make([]byte, headerSize)
	copy(buf[offMagic:], magic)
	binary.BigEndian.PutUint16(buf[offVersion:], headerVersion)
	buf[offKDF] = kdfArgon2id
	binary.BigEndian.PutUint32(buf[offTime:], h.params.Time)
	binary.BigEndian.PutUint32(buf[offMemory:], h.params.Memory)
	buf[offThreads] = h.params.Threads
	copy(buf[offSalt:], h.salt[:])
	copy(buf[offNonceDEK:], h.nonceDEK[:])
	copy(buf[offEncDEK:], h.encDEK[:])
	copy(buf[offNonceData:], h.nonceData[:])

	return buf
}

// ParseHeader parses and validates the header at the start of a vault file.
// It does not check the password.
func ParseHeader(buf []byte) (*Header, error) {
	if len(buf) < headerSize+tagSize {
		return nil, ErrNotVault
	}

	if string(buf[:len(magic)]) != magic {
		return nil, ErrNotVault
	}

	if binary.BigEndian.Uint16(buf[offVersion:offKDF]) != headerVersion {
		return nil, ErrUnsupportedVersion
	}

	if buf[offKDF] != kdfArgon2id {
		return nil, ErrUnsupportedVersion
	}

	h := &Header{}

	h.params.Time = binary.BigEndian.Uint32(buf[offTime:offMemory])
	h.params.Memory = binary.BigEndian.Uint32(buf[offMemory:offThreads])
	h.params.Threads = buf[offThreads]

	if err := h.params.validate(); err != nil {
		return nil, err
	}

	copy(h.salt[:], buf[offSalt:offNonceDEK])
	copy(h.nonceDEK[:], buf[offNonceDEK:offEncDEK])
	copy(h.encDEK[:], buf[offEncDEK:offNonceData])
	copy(h.nonceData[:], buf[offNonceData:headerSize])

	return h, nil
}
