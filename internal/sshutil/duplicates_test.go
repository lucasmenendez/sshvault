package sshutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshvault/internal/vault"
)

func duplicateFixture(t *testing.T) (*Manager, []*vault.Host) {
	t.Helper()
	m := testManager(t, t.TempDir())
	hosts := []*vault.Host{
		{ID: vault.NewHostID(), Patterns: []string{"alpha"}, HostName: "alpha.example.com", User: "new"},
		{ID: vault.NewHostID(), Patterns: []string{"beta"}, HostName: "beta.example.com", User: "new"},
	}
	deployed := map[string]bool{}
	for _, h := range hosts {
		deployed[h.ID] = true
	}
	if _, err := m.WriteManaged(hosts, nil, deployed); err != nil {
		t.Fatal(err)
	}
	external := `
Host alpha
    HostName old-alpha.example.com
    User old

Host beta extra
    HostName old-beta.example.com
    User old

Host unrelated
    User someone

Match host foo
    User matched

Host aftermatch
    HostName z.example.com
`
	f, err := os.OpenFile(m.ConfigPath(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(external); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return m, hosts
}

func TestDuplicateReport(t *testing.T) {
	m, hosts := duplicateFixture(t)
	report, err := m.DuplicateReport(hosts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Items) != 2 {
		t.Fatalf("items = %#v", report.Items)
	}
	alpha := report.Items[0]
	if len(alpha.Patterns) != 1 || alpha.Patterns[0] != "alpha" {
		t.Fatalf("alpha = %#v", alpha)
	}
	if !strings.Contains(alpha.External, "Host alpha") || !strings.Contains(alpha.Managed, "Host alpha") {
		t.Fatalf("alpha blocks = %#v", alpha)
	}
	if alpha.Mixed {
		t.Fatalf("alpha should not be mixed")
	}
	beta := report.Items[1]
	if !beta.Mixed {
		t.Fatalf("beta should be mixed: %#v", beta)
	}
	if len(beta.AllPatterns) != 2 || len(beta.Patterns) != 1 {
		t.Fatalf("beta patterns = %#v", beta)
	}
	if report.ConfigHash == "" {
		t.Fatal("missing config hash")
	}
}

func TestResolveCommentAndSplit(t *testing.T) {
	m, hosts := duplicateFixture(t)
	report, err := m.DuplicateReport(hosts, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := m.ResolveDuplicate(hosts, nil, report.ConfigHash, report.Items[0].ID, DuplicateActionComment)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 1 {
		t.Fatalf("remaining = %#v", next.Items)
	}
	b, err := os.ReadFile(m.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(b)
	if !strings.Contains(cfg, "# Host alpha") || !strings.Contains(cfg, "#     HostName old-alpha.example.com") {
		t.Fatalf("alpha was not commented:\n%s", cfg)
	}
	if !strings.Contains(cfg, "Host unrelated") || !strings.Contains(cfg, "Match host foo") {
		t.Fatalf("unrelated config was lost:\n%s", cfg)
	}
	if !strings.Contains(cfg, ConfigBeginMarker) {
		t.Fatalf("managed block was lost:\n%s", cfg)
	}
	backups, err := os.ReadDir(filepath.Join(m.Dir, ".sshvault-backups"))
	if err != nil || len(backups) == 0 {
		t.Fatalf("expected a config backup: %v", err)
	}

	beta := next.Items[0]
	next2, err := m.ResolveDuplicate(hosts, nil, next.ConfigHash, beta.ID, DuplicateActionSplit)
	if err != nil {
		t.Fatal(err)
	}
	if len(next2.Items) != 0 {
		t.Fatalf("remaining after split = %#v", next2.Items)
	}
	b, _ = os.ReadFile(m.ConfigPath())
	cfg = string(b)
	if !strings.Contains(cfg, "Host extra") {
		t.Fatalf("non-duplicate pattern was not preserved:\n%s", cfg)
	}
	if strings.Contains(cfg, "Host beta extra") {
		t.Fatalf("duplicate pattern still in the Host line:\n%s", cfg)
	}
	if !strings.Contains(cfg, "HostName old-beta.example.com") {
		t.Fatalf("options were lost:\n%s", cfg)
	}
}

func TestResolveRemove(t *testing.T) {
	m, hosts := duplicateFixture(t)
	report, err := m.DuplicateReport(hosts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveDuplicate(hosts, nil, report.ConfigHash, report.Items[0].ID, DuplicateActionRemove); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.ConfigPath())
	cfg := string(b)
	if strings.Contains(cfg, "HostName old-alpha.example.com") {
		t.Fatalf("alpha external block was not removed:\n%s", cfg)
	}
	if !strings.Contains(cfg, "Host alpha\n") {
		t.Fatalf("managed alpha block was lost:\n%s", cfg)
	}
	if !strings.Contains(cfg, "Host beta extra") || !strings.Contains(cfg, "Host unrelated") {
		t.Fatalf("other config was lost:\n%s", cfg)
	}
}

func TestResolveErrors(t *testing.T) {
	m, hosts := duplicateFixture(t)
	report, err := m.DuplicateReport(hosts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveDuplicate(hosts, nil, "wrong", report.Items[0].ID, DuplicateActionComment); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("err = %v, want ErrConfigChanged", err)
	}
	if _, err := m.ResolveDuplicate(hosts, nil, report.ConfigHash, "nope", DuplicateActionComment); !errors.Is(err, ErrDuplicateNotFound) {
		t.Fatalf("err = %v, want ErrDuplicateNotFound", err)
	}
	if _, err := m.ResolveDuplicate(hosts, nil, report.ConfigHash, report.Items[0].ID, "nope"); err == nil {
		t.Fatal("expected invalid action error")
	}
}

func TestDuplicateMalformedMarkers(t *testing.T) {
	m := testManager(t, t.TempDir())
	if err := os.WriteFile(m.ConfigPath(), []byte(ConfigBeginMarker+"\nHost x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host := &vault.Host{ID: vault.NewHostID(), Patterns: []string{"x"}}
	if _, err := m.DuplicateReport([]*vault.Host{host}, nil); err == nil {
		t.Fatal("expected malformed markers error")
	}
}
