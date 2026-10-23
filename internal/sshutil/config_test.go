package sshutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshvault/internal/vault"
)

func configFixture(t *testing.T) (*Manager, *vault.Key, *vault.Host) {
	t.Helper()
	dir := t.TempDir()
	m := testManager(t, dir)
	k := testKey(t, "alpha")
	h := &vault.Host{
		ID:             vault.NewHostID(),
		Patterns:       []string{"testhost"},
		HostName:       "example.com",
		User:           "deploy",
		Port:           2222,
		IdentityKeyIDs: []string{k.ID},
		Options:        []vault.Option{{Name: "IdentitiesOnly", Value: "yes"}},
	}
	return m, k, h
}

func TestWriteManagedPreservesForeignConfig(t *testing.T) {
	m, k, h := configFixture(t)
	foreign := "# my settings\nHost other\n    User old\n"
	if err := os.WriteFile(m.ConfigPath(), []byte(foreign), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(m.ConfigPath(), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(m.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.HasPrefix(got, ConfigBeginMarker) {
		t.Fatalf("managed block is not at the top:\n%s", got)
	}
	if !strings.Contains(got, foreign) {
		t.Fatalf("foreign config was lost:\n%s", got)
	}
	if !strings.Contains(got, "Host testhost") || !strings.Contains(got, "HostName example.com") {
		t.Fatalf("host missing:\n%s", got)
	}
	info, err := os.Stat(m.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestDeployedHostIDsAndStatus(t *testing.T) {
	m, k, h := configFixture(t)
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true}); err != nil {
		t.Fatal(err)
	}
	_, ids, err := m.ConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !ids[h.ID] {
		t.Fatalf("deployed ids = %#v", ids)
	}
	statuses, err := m.HostStatuses([]*vault.Host{h}, []*vault.Key{k})
	if err != nil {
		t.Fatal(err)
	}
	if statuses[h.ID].State != StateDeployed {
		t.Fatalf("status = %+v", statuses[h.ID])
	}
	// Edit the managed block behind the app's back.
	b, _ := os.ReadFile(m.ConfigPath())
	edited := strings.Replace(string(b), "User deploy", "User other", 1)
	if err := os.WriteFile(m.ConfigPath(), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	statuses, err = m.HostStatuses([]*vault.Host{h}, []*vault.Key{k})
	if err != nil {
		t.Fatal(err)
	}
	if statuses[h.ID].State != StateDrift {
		t.Fatalf("status = %+v", statuses[h.ID])
	}
}

func TestRemoveManagedBlock(t *testing.T) {
	m, k, h := configFixture(t)
	foreign := "Host other\n    User old\n"
	if err := os.WriteFile(m.ConfigPath(), []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(m.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, ConfigBeginMarker) || strings.Contains(got, ConfigEndMarker) {
		t.Fatalf("markers remain:\n%s", got)
	}
	if !strings.Contains(got, foreign) {
		t.Fatalf("foreign config was lost:\n%s", got)
	}
}

func TestMalformedMarkers(t *testing.T) {
	m, k, h := configFixture(t)
	if err := os.WriteFile(m.ConfigPath(), []byte(ConfigBeginMarker+"\nHost broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.HostStatuses([]*vault.Host{h}, []*vault.Key{k}); err == nil {
		t.Fatal("expected malformed marker error")
	}
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true}); err == nil {
		t.Fatal("expected malformed marker error on write")
	}
}

func TestDuplicateMarkers(t *testing.T) {
	m, _, _ := configFixture(t)
	content := ConfigBeginMarker + "\n" + ConfigEndMarker + "\n" + ConfigBeginMarker + "\n" + ConfigEndMarker + "\n"
	if err := os.WriteFile(m.ConfigPath(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ManagedBlock(); err == nil {
		t.Fatal("expected duplicate marker error")
	}
}

func TestConfigWarnings(t *testing.T) {
	m, k, h := configFixture(t)
	other := &vault.Host{ID: vault.NewHostID(), Patterns: []string{"other"}}
	if err := os.WriteFile(m.ConfigPath(), []byte("Host other\n    User old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true}); err != nil {
		t.Fatal(err)
	}
	warnings, err := m.ConfigWarnings([]*vault.Host{other})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "other") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestConfigSymlinkPreserved(t *testing.T) {
	m, k, h := configFixture(t)
	target := filepath.Join(m.Dir, "dotfiles-config")
	if err := os.WriteFile(target, []byte("Host other\n    User old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.ConfigPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteManaged([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(m.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("config symlink was replaced")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Host testhost") {
		t.Fatalf("target was not updated:\n%s", b)
	}
}

func TestRenderBlockEmpty(t *testing.T) {
	if got := RenderBlock(nil, nil, nil, func(s string) string { return s }); got != "" {
		t.Fatalf("block = %q", got)
	}
}

func TestConfigPreview(t *testing.T) {
	m, k, h := configFixture(t)
	if err := os.WriteFile(m.ConfigPath(), []byte("Host other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := m.ConfigPreview([]*vault.Host{h}, []*vault.Key{k}, map[string]bool{h.ID: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(preview, ConfigBeginMarker) || !strings.Contains(preview, "Host other") {
		t.Fatalf("preview:\n%s", preview)
	}
}
