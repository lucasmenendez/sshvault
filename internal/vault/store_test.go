package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const testPassword = "password123"

func writeTestVault(t *testing.T, path string) {
	t.Helper()
	v := NewVault()
	plain, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	blob, _, _, err := EncryptNew(plain, testPassword, testKDF())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openTestVault(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateOpenUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.vault")
	if _, err := Create(path, "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
	s, err := Create(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	rev := int64(1)
	updated, err := s.Update(rev, func(v *Vault) error {
		v.Keys = append(v.Keys, &Key{
			ID: NewKeyID(), Alias: "a", Filename: "id_a", Kind: KeyKindPublic,
			PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA a\n",
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != rev+1 {
		t.Fatalf("revision = %d", updated.Revision)
	}
	if _, err := s.Update(rev, func(v *Vault) error { return nil }); !errors.Is(err, ErrRevision) {
		t.Fatalf("err = %v, want ErrRevision", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Opening with the wrong password must fail.
	if _, err := Open(path, "wrongpassword"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
	s2, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	snap, err := s2.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Keys) != 1 || snap.Keys[0].Alias != "a" {
		t.Fatalf("keys = %#v", snap.Keys)
	}
}

func TestVaultNotFound(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing.vault"), testPassword)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestOpenLockedExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	writeTestVault(t, path)
	s, err := OpenLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.IsLocked() || s.NeedsSetup() {
		t.Fatalf("locked=%v needsSetup=%v", s.IsLocked(), s.NeedsSetup())
	}
	if _, err := s.Snapshot(); !errors.Is(err, ErrLocked) {
		t.Fatalf("snapshot err = %v", err)
	}
	if err := s.Unlock(testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenLockedMissingAndCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	s, err := OpenLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.IsLocked() || !s.NeedsSetup() {
		t.Fatalf("locked=%v needsSetup=%v", s.IsLocked(), s.NeedsSetup())
	}
	if err := s.Unlock(testPassword); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlock missing err = %v", err)
	}
	if err := s.Create("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("short create err = %v", err)
	}
	if err := s.Create(testPassword); err != nil {
		t.Fatal(err)
	}
	if s.IsLocked() || s.NeedsSetup() {
		t.Fatalf("locked=%v needsSetup=%v", s.IsLocked(), s.NeedsSetup())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(testPassword); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("second create err = %v", err)
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
}

func TestLockedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	writeTestVault(t, path)
	s := openTestVault(t, path)
	s.Lock()
	if _, err := s.Snapshot(); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	if err := s.Unlock("wrongpassword"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
	if err := s.Unlock(testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
}

func TestInUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	writeTestVault(t, path)
	s := openTestVault(t, path)
	if _, err := Open(path, testPassword); !errors.Is(err, ErrInUse) {
		t.Fatalf("err = %v, want ErrInUse", err)
	}
	_ = s
}

func TestChangePassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	writeTestVault(t, path)
	s := openTestVault(t, path)
	if err := s.ChangePassword("wrongpassword", "newpassword"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
	if err := s.ChangePassword(testPassword, "newpassword"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testPassword); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("old password still works: %v", err)
	}
	s2, err := Open(path, "newpassword")
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Close()
}

func TestBackupsAreRotated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.vault")
	writeTestVault(t, path)
	s := openTestVault(t, path)
	for i := 0; i < 8; i++ {
		if _, err := s.Update(0, func(v *Vault) error {
			v.UpdatedAt = v.UpdatedAt.Add(1)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := filepath.Glob(path + ".bak.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != backupKeepCount {
		t.Fatalf("backups = %d, want %d", len(matches), backupKeepCount)
	}
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("backup mode = %o", info.Mode().Perm())
		}
	}
}

func TestSymlinkIsPreserved(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.vault")
	link := filepath.Join(dir, "link.vault")
	writeTestVault(t, real)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	s, err := Open(link, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(0, func(v *Vault) error {
		v.UpdatedAt = v.UpdatedAt.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	if _, err := Open(link, testPassword); err != nil {
		t.Fatal(err)
	}
}

func TestCreateExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	s, err := Create(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, testPassword); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("err = %v, want ErrVaultExists", err)
	}
}
