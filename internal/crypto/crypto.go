// Package crypto implements vault file encryption: header layout, key derivation and sealing.
package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magic                = "RPWD"
	headerVersion uint16 = 1
	versionSize          = 2
	kdfIDSize            = 1
	kdfArgon2id   uint8  = 1
	saltSize             = 16
	keySize              = chacha20poly1305.KeySize
	nonceSize            = chacha20poly1305.NonceSizeX
	tagSize              = chacha20poly1305.Overhead
	encDEKSize           = keySize + tagSize
	timeSize             = 4
	memorySize           = 4
	threadsSize          = 1
	dekAADEnd            = offNonceDEK
	dataAADEnd           = headerSize

	offMagic     = 0
	offVersion   = offMagic + len(magic)    // 4
	offKDF       = offVersion + versionSize // 6
	offTime      = offKDF + kdfIDSize       // 7
	offMemory    = offTime + timeSize       // 11
	offThreads   = offMemory + memorySize   // 15
	offSalt      = offThreads + threadsSize // 16
	offNonceDEK  = offSalt + saltSize       // 32
	offEncDEK    = offNonceDEK + nonceSize  // 56
	offNonceData = offEncDEK + encDEKSize   // 104
	headerSize   = offNonceData + nonceSize // 128

	minThreads = 1
	maxThreads = 16

	minTime = 1
	maxTime = 10

	minMemory = 8 * 1024
	maxMemory = 1024 * 1024
)

var (
	ErrNotVault           = errors.New("not an rpwd vault")
	ErrUnsupportedVersion = errors.New("unsupported vault version")
	ErrCorrupted          = errors.New("vault is corrupted")
	ErrWrongPassword      = errors.New("wrong master password")
)

type Params struct {
	Time    uint32 // проходы
	Memory  uint32 // KiB
	Threads uint8
}

var defaultParams = Params{Time: 3, Memory: 64 * 1024, Threads: 4}

func (p Params) validate() error {
	fields := []struct {
		name     string
		val      uint32
		min, max uint32
	}{
		{"time", p.Time, minTime, maxTime},
		{"memory", p.Memory, minMemory, maxMemory},
		{"threads", uint32(p.Threads), minThreads, maxThreads},
	}

	for _, f := range fields {
		if f.val < f.min || f.val > f.max {
			return fmt.Errorf("%w: argon2 %s %d out of range [%d, %d]",
				ErrCorrupted, f.name, f.val, f.min, f.max)
		}
	}

	return nil
}
