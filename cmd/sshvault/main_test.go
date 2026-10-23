package main

import (
	"os"
	"path/filepath"
	"testing"

	"sshvault/internal/preferences"
	"sshvault/internal/sshutil"
)

func TestChooseVaultPath(t *testing.T) {
	dir := t.TempDir()
	manager, err := sshutil.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	path, isDefault := chooseVaultPath("", manager)
	if want := filepath.Join(manager.Dir, "ssh.vault"); path != want || !isDefault {
		t.Fatalf("default path = %q, %v; want %q, true", path, isDefault, want)
	}
	path, isDefault = chooseVaultPath("/tmp/custom.vault", manager)
	if path != "/tmp/custom.vault" || isDefault {
		t.Fatalf("explicit path = %q, %v", path, isDefault)
	}
}

func TestChooseVaultPathWithRememberedVault(t *testing.T) {
	dir := t.TempDir()
	manager, err := sshutil.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	remembered := filepath.Join(dir, "remembered.vault")
	if err := os.WriteFile(remembered, []byte("vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	prefs, err := preferences.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := prefs.SetRemember(true, remembered); err != nil {
		t.Fatal(err)
	}

	path, isDefault := chooseVaultPathWithPrefs("", manager, prefs, false)
	if path != remembered || isDefault {
		t.Fatalf("remembered path = %q, %v; want %q, false", path, isDefault, remembered)
	}

	path, isDefault = chooseVaultPathWithPrefs("", manager, prefs, true)
	if want := filepath.Join(manager.Dir, "ssh.vault"); path != want || !isDefault {
		t.Fatalf("explicit ssh-dir path = %q, %v; want %q, true", path, isDefault, want)
	}

	path, isDefault = chooseVaultPathWithPrefs("/tmp/custom.vault", manager, prefs, false)
	if path != "/tmp/custom.vault" || isDefault {
		t.Fatalf("explicit path = %q, %v", path, isDefault)
	}
}

func TestChooseVaultPathFallsBackWhenRememberedIsMissing(t *testing.T) {
	dir := t.TempDir()
	manager, err := sshutil.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	prefs, err := preferences.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := prefs.SetRemember(true, filepath.Join(dir, "missing.vault")); err != nil {
		t.Fatal(err)
	}
	path, isDefault := chooseVaultPathWithPrefs("", manager, prefs, false)
	if want := filepath.Join(manager.Dir, "ssh.vault"); path != want || !isDefault {
		t.Fatalf("fallback path = %q, %v; want %q, true", path, isDefault, want)
	}
}

func TestChooseVaultPathUsesHomeSSHDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	manager, err := sshutil.NewManager("")
	if err != nil {
		t.Fatal(err)
	}
	path, isDefault := chooseVaultPath("", manager)
	want := filepath.Join(home, ".ssh", "ssh.vault")
	if path != want || !isDefault {
		t.Fatalf("path = %q, %v; want %q, true", path, isDefault, want)
	}
}

func TestLegacyVaultHint(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := t.TempDir()
	manager, err := sshutil.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	defaultPath := filepath.Join(manager.Dir, "ssh.vault")
	if hint := legacyVaultHint(defaultPath, true); hint != "" {
		t.Fatalf("unexpected hint without legacy file: %q", hint)
	}
	if err := os.WriteFile("ssh.vault", []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hint := legacyVaultHint(defaultPath, true); hint != "./ssh.vault" {
		t.Fatalf("hint = %q, want ./ssh.vault", hint)
	}
	if hint := legacyVaultHint(defaultPath, false); hint != "" {
		t.Fatalf("explicit path hint = %q, want empty", hint)
	}
}
