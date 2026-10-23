package preferences

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSetRememberWritesPrivateConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := m.Config(); cfg.RememberVault || cfg.LastVaultPath != "" {
		t.Fatalf("initial config = %#v", cfg)
	}

	if err := m.SetRemember(true, "/vaults/work.vault"); err != nil {
		t.Fatal(err)
	}
	if cfg := m.Config(); !cfg.RememberVault || cfg.LastVaultPath != "/vaults/work.vault" {
		t.Fatalf("config = %#v", cfg)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Config
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if !onDisk.RememberVault || onDisk.LastVaultPath != "/vaults/work.vault" {
		t.Fatalf("on-disk config = %#v", onDisk)
	}

	if err := m.Remember("/vaults/other.vault"); err != nil {
		t.Fatal(err)
	}
	if cfg := m.Config(); cfg.LastVaultPath != "/vaults/other.vault" {
		t.Fatalf("after remember = %#v", cfg)
	}

	if err := m.SetRemember(false, ""); err != nil {
		t.Fatal(err)
	}
	if cfg := m.Config(); cfg.RememberVault || cfg.LastVaultPath != "" {
		t.Fatalf("after disabling = %#v", cfg)
	}
}

func TestRememberIsNoopWhenDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Remember("/vaults/work.vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config file should not be created while disabled: %v", err)
	}
}

func TestOpenMissingReturnsEmptyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.json")
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := m.Config(); cfg.RememberVault || cfg.LastVaultPath != "" {
		t.Fatalf("config = %#v", cfg)
	}
}
