package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrNotFound     = errors.New("vault file not found")
	ErrEmptyVault   = errors.New("vault file is empty")
	ErrLocked       = errors.New("vault is locked")
	ErrInUse        = errors.New("vault is in use by another sshvault process")
	ErrRevision     = errors.New("vault was modified by another session")
	ErrWeakPassword = errors.New("password must be at least 8 characters")
	ErrVaultExists  = errors.New("vault file already exists")
	backupKeepCount = 5
)

// Store owns an unlocked vault document and its on-disk encrypted container.
type Store struct {
	path string

	mu         sync.Mutex
	lock       *os.File
	key        []byte
	salt       []byte
	params     KDFParams
	data       *Vault
	locked     bool
	needsSetup bool
	closed     bool
}

// Open unlocks an existing vault and takes an exclusive process lock.
func Open(path, password string) (*Store, error) {
	target, err := resolveTarget(path)
	if err != nil {
		return nil, err
	}
	lf, err := acquireLock(target + ".lock")
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(target)
	if err != nil {
		releaseLock(lf)
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	plain, key, salt, params, err := DecryptBlob(blob, password)
	if err != nil {
		releaseLock(lf)
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(plain, &v); err != nil {
		releaseLock(lf)
		return nil, fmt.Errorf("%w: %v", ErrCorruptVault, err)
	}
	v.Normalize()
	if err := v.Validate(); err != nil {
		releaseLock(lf)
		return nil, fmt.Errorf("%w: %v", ErrCorruptVault, err)
	}
	return &Store{
		path:   target,
		lock:   lf,
		key:    key,
		salt:   salt,
		params: params,
		data:   &v,
	}, nil
}

// OpenLocked takes the process lock without decrypting the vault. The returned
// store is locked; NeedsSetup reports whether the file does not exist yet. An
// existing empty file is rejected because it is not a usable vault.
func OpenLocked(path string) (*Store, error) {
	return openLocked(path, false)
}

// OpenLockedForCreate is like OpenLocked, but a missing path or an existing
// zero-byte file is accepted as a place where Create may initialize a vault.
// Any non-empty file is rejected so it can never be overwritten accidentally.
func OpenLockedForCreate(path string) (*Store, error) {
	return openLocked(path, true)
}

func openLocked(path string, forCreate bool) (*Store, error) {
	if forCreate {
		// The explicit creation flow may target a new directory such as
		// ~/vaults/ssh.vault. Create the parent chain before resolving the
		// target so the canonical path is stable. Never do this for ordinary
		// "open existing" actions.
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return nil, fmt.Errorf("create vault directory: %w", err)
		}
	}
	target, err := resolveTarget(path)
	if err != nil {
		return nil, err
	}
	lf, err := acquireLock(target + ".lock")
	if err != nil {
		return nil, err
	}
	needsSetup := false
	if info, err := os.Stat(target); err != nil {
		if !os.IsNotExist(err) {
			releaseLock(lf)
			return nil, err
		}
		needsSetup = true
	} else if info.IsDir() {
		releaseLock(lf)
		return nil, fmt.Errorf("vault path %s is a directory", target)
	} else if !info.Mode().IsRegular() {
		releaseLock(lf)
		return nil, fmt.Errorf("vault path %s is not a regular file", target)
	} else if info.Size() == 0 {
		if !forCreate {
			releaseLock(lf)
			return nil, ErrEmptyVault
		}
		needsSetup = true
	} else if forCreate {
		releaseLock(lf)
		return nil, ErrVaultExists
	}
	return &Store{path: target, lock: lf, locked: true, needsSetup: needsSetup}, nil
}

// NeedsSetup reports whether this locked store points to a vault that does not
// exist yet and must be created before it can be unlocked.
func (s *Store) NeedsSetup() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.needsSetup && !s.closed
}

// Create writes a new empty vault and takes the process lock.
func Create(path, password string) (*Store, error) {
	if len(password) < 8 {
		return nil, ErrWeakPassword
	}
	target, err := resolveTarget(path)
	if err != nil {
		return nil, err
	}
	lf, err := acquireLock(target + ".lock")
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(target); err == nil {
		releaseLock(lf)
		return nil, ErrVaultExists
	} else if !os.IsNotExist(err) {
		releaseLock(lf)
		return nil, err
	}
	v := NewVault()
	plain, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		releaseLock(lf)
		return nil, err
	}
	params := DefaultKDFParams()
	blob, key, salt, err := EncryptNew(plain, password, params)
	if err != nil {
		releaseLock(lf)
		return nil, err
	}
	if err := writeAtomic(target, blob, 0o600); err != nil {
		releaseLock(lf)
		return nil, err
	}
	return &Store{
		path:   target,
		lock:   lf,
		key:    key,
		salt:   salt,
		params: params,
		data:   v,
	}, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) IsLocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked || s.closed
}

// Snapshot returns a deep copy of the current document.
func (s *Store) Snapshot() (*Vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrLocked
	}
	if s.locked || s.data == nil {
		return nil, ErrLocked
	}
	return s.data.Clone()
}

// Update applies fn to a copy, validates it, persists it and swaps it in.
// If expectedRevision is non-zero it must match the current revision.
func (s *Store) Update(expectedRevision int64, fn func(*Vault) error) (*Vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrLocked
	}
	if s.locked || s.data == nil {
		return nil, ErrLocked
	}
	if expectedRevision != 0 && expectedRevision != s.data.Revision {
		return nil, ErrRevision
	}
	next, err := s.data.Clone()
	if err != nil {
		return nil, err
	}
	if err := fn(next); err != nil {
		return nil, err
	}
	next.Normalize()
	next.Revision = s.data.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := s.saveLocked(next); err != nil {
		return nil, err
	}
	s.data = next
	return next.Clone()
}

func (s *Store) saveLocked(v *Vault) error {
	plain, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if len(plain) > MaxVaultSize {
		return SizeLimitError("vault", len(plain), MaxVaultSize)
	}
	blob, err := SealBlob(plain, s.key, s.salt, s.params)
	if err != nil {
		return err
	}
	if _, err := os.Stat(s.path); err == nil {
		if err := backupFile(s.path, backupKeepCount); err != nil {
			return fmt.Errorf("cannot create vault backup: %w", err)
		}
	}
	return writeAtomic(s.path, blob, 0o600)
}

// VerifyPassword checks a password against the currently unlocked vault.
func (s *Store) VerifyPassword(password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked || len(s.key) == 0 {
		return false
	}
	candidate := DeriveKey(password, s.salt, s.params)
	return KeysEqual(candidate, s.key)
}

// ChangePassword re-encrypts the vault with a new password and salt.
func (s *Store) ChangePassword(current, next string) error {
	if len(next) < 8 {
		return ErrWeakPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.locked || s.data == nil {
		return ErrLocked
	}
	candidate := DeriveKey(current, s.salt, s.params)
	if !KeysEqual(candidate, s.key) {
		return ErrInvalidPassword
	}
	newSalt := randomBytes(saltLen)
	newKey := DeriveKey(next, newSalt, s.params)
	plain, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	blob, err := SealBlob(plain, newKey, newSalt, s.params)
	if err != nil {
		return err
	}
	if err := backupFile(s.path, backupKeepCount); err != nil {
		return fmt.Errorf("cannot create vault backup: %w", err)
	}
	if err := writeAtomic(s.path, blob, 0o600); err != nil {
		return err
	}
	Zero(s.key)
	s.key = newKey
	s.salt = newSalt
	return nil
}

// Create initializes a missing vault represented by this locked store.
func (s *Store) Create(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrLocked
	}
	if !s.needsSetup {
		return ErrVaultExists
	}
	if info, err := os.Stat(s.path); err == nil {
		// Create may initialize a zero-byte placeholder, but never replace a
		// file that contains data.
		if !info.Mode().IsRegular() || info.Size() != 0 {
			return ErrVaultExists
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	v := NewVault()
	plain, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	params := DefaultKDFParams()
	blob, key, salt, err := EncryptNew(plain, password, params)
	if err != nil {
		return err
	}
	if err := writeAtomic(s.path, blob, 0o600); err != nil {
		return err
	}
	s.key = key
	s.salt = salt
	s.params = params
	s.data = v
	s.locked = false
	s.needsSetup = false
	return nil
}

// Lock discards the decrypted document and key material but keeps the file lock.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.locked {
		return
	}
	Zero(s.key)
	s.key = nil
	s.salt = nil
	s.data = nil
	s.locked = true
}

// Unlock re-reads the vault from disk and derives the key again.
func (s *Store) Unlock(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrLocked
	}
	if !s.locked {
		return nil
	}
	if s.needsSetup {
		return ErrNotFound
	}
	blob, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	plain, key, salt, params, err := DecryptBlob(blob, password)
	if err != nil {
		return err
	}
	var v Vault
	if err := json.Unmarshal(plain, &v); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptVault, err)
	}
	v.Normalize()
	if err := v.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptVault, err)
	}
	s.key = key
	s.salt = salt
	s.params = params
	s.data = &v
	s.locked = false
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	Zero(s.key)
	s.key = nil
	s.salt = nil
	s.data = nil
	if s.lock != nil {
		releaseLock(s.lock)
		s.lock = nil
	}
	return nil
}

func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrInUse
		}
		return nil, err
	}
	return f, nil
}

func releaseLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

// ResolvePath returns the canonical path used for a vault. Existing symlinks
// are resolved; for a missing file, the containing directory is resolved so
// that path comparisons remain stable.
func ResolvePath(path string) (string, error) {
	return resolveTarget(path)
}

func resolveTarget(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	dir := filepath.Dir(abs)
	if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(resolvedDir, filepath.Base(abs)), nil
	}
	return abs, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sshvault-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func backupFile(path string, keep int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000")
	bak := path + ".bak." + stamp
	if err := os.WriteFile(bak, data, 0o600); err != nil {
		return err
	}
	pruneBackups(path, keep)
	return nil
}

func pruneBackups(path string, keep int) {
	matches, err := filepath.Glob(path + ".bak.*")
	if err != nil || len(matches) <= keep {
		return
	}
	sort.Strings(matches)
	for _, old := range matches[:len(matches)-keep] {
		if strings.HasPrefix(filepath.Base(old), filepath.Base(path)+".bak.") {
			_ = os.Remove(old)
		}
	}
}
