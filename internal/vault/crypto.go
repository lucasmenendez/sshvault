package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magicString   = "SSHVAULT"
	formatVersion = 1
	kdfArgon2id   = 1

	keyLen    = 32
	saltLen   = 16
	nonceLen  = 24
	headerLen = 8 + 1 + 1 + 4 + 4 + 1 + saltLen + nonceLen
)

var (
	// ErrInvalidPassword is returned when the AEAD cannot authenticate the
	// payload. This is deliberately indistinguishable from a corrupted file.
	ErrInvalidPassword = errors.New("invalid password or corrupted vault")
	// ErrCorruptVault is returned for structural issues in the container.
	ErrCorruptVault = errors.New("corrupted vault file")
)

// KDFParams describes the Argon2id cost parameters stored in the vault header.
type KDFParams struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultKDFParams is the cost used for new vaults.
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}
}

func (p KDFParams) validate() error {
	if p.Time < 1 || p.Time > 10 {
		return fmt.Errorf("%w: invalid Argon2 time parameter", ErrCorruptVault)
	}
	if p.Memory < 8*1024 || p.Memory > 1024*1024 {
		return fmt.Errorf("%w: invalid Argon2 memory parameter", ErrCorruptVault)
	}
	if p.Threads < 1 || p.Threads > 16 {
		return fmt.Errorf("%w: invalid Argon2 thread parameter", ErrCorruptVault)
	}
	return nil
}

// DeriveKey derives the 32-byte vault key from a password.
func DeriveKey(password string, salt []byte, p KDFParams) []byte {
	return argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
}

// KeysEqual compares two derived keys in constant time.
func KeysEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// EncryptNew creates a brand new encrypted container and returns the derived
// key and salt so the caller can keep them for later writes.
func EncryptNew(plaintext []byte, password string, params KDFParams) (blob, key, salt []byte, err error) {
	if err := params.validate(); err != nil {
		return nil, nil, nil, err
	}
	salt = randomBytes(saltLen)
	key = DeriveKey(password, salt, params)
	blob, err = SealBlob(plaintext, key, salt, params)
	if err != nil {
		return nil, nil, nil, err
	}
	return blob, key, salt, nil
}

// DecryptBlob opens an existing container and returns the plaintext plus the
// derived key and parameters needed to re-encrypt future revisions.
func DecryptBlob(blob []byte, password string) (plaintext, key, salt []byte, params KDFParams, err error) {
	params, salt, nonce, ciphertext, aad, err := parseHeader(blob)
	if err != nil {
		return nil, nil, nil, KDFParams{}, err
	}
	key = DeriveKey(password, salt, params)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, nil, KDFParams{}, err
	}
	plaintext, err = aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, nil, nil, KDFParams{}, ErrInvalidPassword
	}
	return plaintext, key, salt, params, nil
}

// SealBlob encrypts plaintext with an already-derived key. A fresh nonce is
// generated for every call.
func SealBlob(plaintext, key, salt []byte, params KDFParams) ([]byte, error) {
	if len(key) != keyLen {
		return nil, errors.New("vault: invalid key length")
	}
	if len(salt) != saltLen {
		return nil, errors.New("vault: invalid salt length")
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	nonce := randomBytes(nonceLen)
	header := make([]byte, headerLen)
	copy(header[0:8], magicString)
	header[8] = formatVersion
	header[9] = kdfArgon2id
	binary.BigEndian.PutUint32(header[10:14], params.Time)
	binary.BigEndian.PutUint32(header[14:18], params.Memory)
	header[18] = params.Threads
	copy(header[19:35], salt)
	copy(header[35:59], nonce)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(plaintext)+aead.Overhead())
	out = append(out, header...)
	out = aead.Seal(out, nonce, plaintext, header)
	return out, nil
}

func parseHeader(blob []byte) (KDFParams, []byte, []byte, []byte, []byte, error) {
	if len(blob) < headerLen+16 {
		return KDFParams{}, nil, nil, nil, nil, ErrCorruptVault
	}
	if string(blob[0:8]) != magicString {
		return KDFParams{}, nil, nil, nil, nil, fmt.Errorf("%w: bad magic", ErrCorruptVault)
	}
	if blob[8] != formatVersion {
		return KDFParams{}, nil, nil, nil, nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptVault, blob[8])
	}
	if blob[9] != kdfArgon2id {
		return KDFParams{}, nil, nil, nil, nil, fmt.Errorf("%w: unsupported KDF %d", ErrCorruptVault, blob[9])
	}
	params := KDFParams{
		Time:    binary.BigEndian.Uint32(blob[10:14]),
		Memory:  binary.BigEndian.Uint32(blob[14:18]),
		Threads: blob[18],
	}
	if err := params.validate(); err != nil {
		return KDFParams{}, nil, nil, nil, nil, err
	}
	salt := blob[19:35]
	nonce := blob[35:59]
	ciphertext := blob[59:]
	aad := blob[:59]
	return params, salt, nonce, ciphertext, aad, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("vault: crypto/rand failed: " + err.Error())
	}
	return b
}

// Zero overwrites a byte slice. Go strings cannot be reliably zeroed.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
