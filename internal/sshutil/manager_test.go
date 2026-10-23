package sshutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshvault/internal/vault"
)

func testKey(t *testing.T, alias string) *vault.Key {
	t.Helper()
	priv, pub, fp, err := Generate("ed25519", 0, alias)
	if err != nil {
		t.Fatal(err)
	}
	return &vault.Key{
		ID:          vault.NewKeyID(),
		Alias:       alias,
		Filename:    "id_" + alias,
		Kind:        vault.KeyKindKeypair,
		PrivateKey:  priv,
		PublicKey:   pub,
		Fingerprint: fp,
	}
}

func testManager(t *testing.T, dir string) *Manager {
	t.Helper()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDeployKeyAndDrift(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	k := testKey(t, "alpha")

	st, err := m.DeployKey(k, DeployOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateDeployed {
		t.Fatalf("state = %s (%s)", st.State, st.Message)
	}
	for _, path := range []string{filepath.Join(dir, k.Filename), filepath.Join(dir, k.Filename+".pub")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o644)
		if !strings.HasSuffix(path, ".pub") {
			want = 0o600
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}

	// External modification is detected as drift.
	pubPath := filepath.Join(dir, k.Filename+".pub")
	if err := os.WriteFile(pubPath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := m.KeyStatus(k); st.State != StateDrift {
		t.Fatalf("state = %s, want drift", st.State)
	}
	if _, err := m.DeployKey(k, DeployOptions{}); !IsConflict(err) {
		t.Fatalf("err = %v, want conflict", err)
	}
	if _, err := m.DeployKey(k, DeployOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if st := m.KeyStatus(k); st.State != StateDeployed {
		t.Fatalf("state = %s", st.State)
	}
}

func TestUndeployKey(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	k := testKey(t, "beta")
	if _, err := m.DeployKey(k, DeployOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UndeployKey(k, false); !IsConflict(err) {
		t.Fatalf("err = %v, want conflict without force", err)
	}
	if _, err := m.UndeployKey(k, true); err != nil {
		t.Fatal(err)
	}
	if st := m.KeyStatus(k); st.State != StateNotDeployed {
		t.Fatalf("state = %s", st.State)
	}
}

func TestDeployFileAndBackup(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	f := &vault.File{
		ID:       vault.NewFileID(),
		Filename: "known_hosts",
		Encoding: vault.EncodingUTF8,
		Content:  "one\n",
		Mode:     0o600,
	}
	st, err := m.DeployFile(f, DeployOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateDeployed {
		t.Fatalf("state = %s", st.State)
	}
	// Change the vault version; auto-deploy should back up the previous file.
	f.Content = "two\n"
	if _, err := m.DeployFile(f, DeployOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "two\n" {
		t.Fatalf("content = %q", b)
	}
	backups, err := os.ReadDir(filepath.Join(dir, ".sshvault-backups"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) == 0 {
		t.Fatal("expected a backup of the previous file")
	}
}

func TestSymlinkIsBlocked(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	f := &vault.File{
		ID:       vault.NewFileID(),
		Filename: "linkfile",
		Encoding: vault.EncodingUTF8,
		Content:  "x",
		Mode:     0o600,
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, f.Filename)); err != nil {
		t.Fatal(err)
	}
	if st := m.FileStatus(f); st.State != StateBlocked {
		t.Fatalf("state = %s, want blocked", st.State)
	}
	if _, err := m.DeployFile(f, DeployOptions{Force: true}); !IsConflict(err) {
		t.Fatalf("err = %v, want conflict", err)
	}
}

func TestDisplayPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	m, err := NewManager("~/.ssh")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.DisplayPath("id_test"); got != "~/.ssh/id_test" {
		t.Fatalf("display = %q", got)
	}
	other := testManager(t, t.TempDir())
	if got := other.DisplayPath("id_test"); !filepath.IsAbs(got) {
		t.Fatalf("custom dir should be absolute, got %q", got)
	}
}

func TestIsInternalFilename(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	m.SetVaultPath(filepath.Join(dir, "ssh.vault"))
	cases := map[string]bool{
		"ssh.vault":         true,
		"ssh.vault.lock":    true,
		"ssh.vault.bak.123": true,
		"ssh.vault.notes":   true,
		"foo.vault":         true,
		"foo.vault.notes":   true,
		".sshvault-backups": true,
		"known_hosts":       false,
		"vault.txt":         false,
		"myvault":           false,
	}
	for name, want := range cases {
		if got := m.IsInternalFilename(name); got != want {
			t.Errorf("IsInternalFilename(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestScanExcludesInternalFiles(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	m.SetVaultPath(filepath.Join(dir, "ssh.vault"))
	for _, name := range []string{"ssh.vault", "ssh.vault.lock", "ssh.vault.bak.1", "foo.vault.notes", "known_hosts", "vault.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scan, err := m.Scan(vault.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, item := range scan.Items {
		names = append(names, item.Filename)
	}
	for _, unmanaged := range scan.Unmanaged {
		names = append(names, unmanaged.Name)
	}
	joined := strings.Join(names, ",")
	for _, internal := range []string{"ssh.vault", "ssh.vault.lock", "ssh.vault.bak.1", "foo.vault.notes"} {
		if strings.Contains(joined, internal) {
			t.Fatalf("internal file %q was listed: %v", internal, names)
		}
	}
	if !strings.Contains(joined, "known_hosts") || !strings.Contains(joined, "vault.txt") {
		t.Fatalf("normal files are missing: %v", names)
	}
}

func TestScanExcludesCustomVaultSidecars(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	m.SetVaultPath(filepath.Join(dir, "myvault"))
	for _, name := range []string{"myvault", "myvault.lock", "myvault.bak.1", "other.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scan, err := m.Scan(vault.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range scan.Items {
		if item.Filename == "myvault" || item.Filename == "myvault.lock" || item.Filename == "myvault.bak.1" {
			t.Fatalf("internal file %q was listed", item.Filename)
		}
	}
	found := false
	for _, item := range scan.Items {
		if item.Filename == "other.txt" {
			found = true
		}
	}
	if !found {
		t.Fatal("other.txt was not listed")
	}
}

func TestScanLocal(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "config.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("known_hosts", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	files, err := m.ScanLocal()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "known_hosts") || !strings.Contains(joined, "link") {
		t.Fatalf("scan = %v", names)
	}
}
