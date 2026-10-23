package sshutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshvault/internal/vault"
)

func scanFixture(t *testing.T) (*Manager, string, string) {
	t.Helper()
	dir := t.TempDir()
	m := testManager(t, dir)
	priv, pub, _, err := Generate("ed25519", 0, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	_, pub2, _, err := Generate("ed25519", 0, "standalone")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "standalone.pub"), []byte(pub2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("example.com "+strings.TrimSpace(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "binary.bin"), []byte{0xff, 0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}
	config := "Host test\n    HostName test.example.com\n    User deploy\n    Port 2222\n    IdentityFile ~/.ssh/id_ed25519\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("known_hosts", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "config.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	return m, dir, pub
}

func TestScanAndBuildImport(t *testing.T) {
	m, _, pub := scanFixture(t)
	scan, err := m.Scan(vault.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string][]ImportItem{}
	for _, item := range scan.Items {
		byKind[item.Kind] = append(byKind[item.Kind], item)
	}
	if len(byKind["key"]) != 2 {
		t.Fatalf("keys = %#v", byKind["key"])
	}
	if len(byKind["host"]) != 1 {
		t.Fatalf("hosts = %#v", byKind["host"])
	}
	if len(byKind["file"]) != 3 {
		t.Fatalf("files = %#v", byKind["file"])
	}
	for _, item := range byKind["file"] {
		if item.Filename == "authorized_keys" && !item.Sensitive {
			t.Fatal("authorized_keys should be marked sensitive")
		}
		if item.Filename == "binary.bin" && item.Encoding != vault.EncodingBase64 {
			t.Fatalf("binary encoding = %q", item.Encoding)
		}
	}
	host := byKind["host"][0]
	if host.HostName != "test.example.com" || host.User != "deploy" || host.Port != 2222 {
		t.Fatalf("host = %#v", host)
	}
	if len(host.IdentityFiles) != 1 || host.IdentityFiles[0] != "id_ed25519" {
		t.Fatalf("identity files = %#v", host.IdentityFiles)
	}
	var unmanagedNames []string
	for _, u := range scan.Unmanaged {
		unmanagedNames = append(unmanagedNames, u.Name)
	}
	if !strings.Contains(strings.Join(unmanagedNames, ","), "link") {
		t.Fatalf("unmanaged = %v", unmanagedNames)
	}

	selected := map[string]bool{}
	for _, item := range scan.Items {
		selected[item.TempID] = true
	}
	plan, err := m.BuildImport(vault.NewVault(), selected)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Keys) != 2 || len(plan.Hosts) != 1 || len(plan.Files) != 3 {
		t.Fatalf("plan = keys:%d hosts:%d files:%d", len(plan.Keys), len(plan.Hosts), len(plan.Files))
	}
	var keyID string
	for _, k := range plan.Keys {
		if k.Filename == "id_ed25519" {
			keyID = k.ID
			if k.PrivateKey == "" || k.PublicKey == "" {
				t.Fatalf("key content missing: %#v", k)
			}
		}
	}
	if plan.Hosts[0].IdentityKeyIDs[0] != keyID {
		t.Fatalf("host keys = %#v, key id = %s", plan.Hosts[0].IdentityKeyIDs, keyID)
	}

	v := vault.NewVault()
	v.Keys = plan.Keys
	v.Hosts = plan.Hosts
	v.Files = plan.Files
	v.Normalize()
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	_ = pub
}

func TestScanPairsPublicSuffixes(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	writePair := func(privateName, publicName string) {
		t.Helper()
		priv, pub, _, err := Generate("ed25519", 0, privateName)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, privateName), []byte(priv), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, publicName), []byte(pub), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writePair("foo", "foo.pub")
	writePair("bar", "bar.pub.old")
	writePair("baz", "baz.pub.crdownload")
	// Several public candidates: the lexically first non-exact candidate wins and warns.
	priv, pub, _, err := Generate("ed25519", 0, "multi")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "multi"), []byte(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "multi.pub.crdownload"), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	_, extraPub, _, err := Generate("ed25519", 0, "multi-extra")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "multi.pub.old"), []byte(extraPub), 0o644); err != nil {
		t.Fatal(err)
	}
	writePair("oldkey.old", "oldkey.pub.old")
	// Public only, no matching private.
	_, pub, _, err = Generate("ed25519", 0, "qux")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "qux.pub"), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}

	scan, err := m.Scan(vault.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ImportItem{}
	for _, item := range scan.Items {
		if item.Kind == "key" {
			keys[item.Filename] = item
		}
		if item.Kind == "file" {
			t.Fatalf("unexpected file item: %#v", item)
		}
	}
	if len(keys) != 7 {
		t.Fatalf("keys = %#v", keys)
	}
	if k := keys["foo"]; !k.HasPrivate || !k.HasPublic || k.PublicFile != "foo.pub" {
		t.Fatalf("foo = %#v", k)
	}
	if k := keys["bar"]; !k.HasPrivate || !k.HasPublic || k.PublicFile != "bar.pub.old" {
		t.Fatalf("bar = %#v", k)
	}
	if k := keys["baz"]; !k.HasPrivate || !k.HasPublic || k.PublicFile != "baz.pub.crdownload" {
		t.Fatalf("baz = %#v", k)
	}
	if k := keys["multi"]; !k.HasPrivate || !k.HasPublic || k.PublicFile != "multi.pub.crdownload" || len(k.Warnings) == 0 {
		t.Fatalf("multi = %#v", k)
	}
	if k := keys["oldkey"]; k.HasPrivate || !k.HasPublic || k.PublicFile != "oldkey.pub.old" {
		t.Fatalf("oldkey = %#v", k)
	}
	if k := keys["oldkey.old"]; !k.HasPrivate || k.HasPublic {
		t.Fatalf("oldkey.old = %#v", k)
	}
	if k := keys["qux"]; k.HasPrivate || !k.HasPublic {
		t.Fatalf("qux = %#v", k)
	}

	selected := map[string]bool{}
	for _, item := range scan.Items {
		selected[item.TempID] = true
	}
	plan, err := m.BuildImport(vault.NewVault(), selected)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Keys) != 7 {
		t.Fatalf("imported keys = %d", len(plan.Keys))
	}
	v := vault.NewVault()
	v.Keys = plan.Keys
	v.Normalize()
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, k := range plan.Keys {
		if k.Filename == "bar" && k.PublicKey == "" {
			t.Fatal("bar public key content was not imported")
		}
	}
}

func TestScanConflictsWithExistingVault(t *testing.T) {
	m, dir, _ := scanFixture(t)
	priv, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	existing := &vault.Key{
		ID:         vault.NewKeyID(),
		Alias:      "existing",
		Filename:   "id_ed25519",
		Kind:       vault.KeyKindKeypair,
		PrivateKey: string(priv),
		PublicKey:  string(pub),
	}
	info, err := Inspect(existing)
	if err != nil {
		t.Fatal(err)
	}
	existing.Fingerprint = info.Fingerprint

	current := vault.NewVault()
	current.Keys = []*vault.Key{existing}
	current.Hosts = []*vault.Host{{
		ID:             vault.NewHostID(),
		Patterns:       []string{"existing"},
		IdentityKeyIDs: []string{existing.ID},
	}}

	scan, err := m.Scan(current)
	if err != nil {
		t.Fatal(err)
	}
	foundConflict := false
	for _, item := range scan.Items {
		if item.Kind == "key" && item.Filename == "id_ed25519" {
			foundConflict = item.Conflict == "already in vault"
		}
	}
	if !foundConflict {
		t.Fatalf("expected key conflict: %#v", scan.Items)
	}
	selected := map[string]bool{}
	for _, item := range scan.Items {
		selected[item.TempID] = true
	}
	plan, err := m.BuildImport(current, selected)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Keys) != 1 {
		// standalone.pub is still new; id_ed25519 is already in the vault.
		t.Fatalf("new keys = %d", len(plan.Keys))
	}
	if plan.Keys[0].Filename != "standalone" {
		t.Fatalf("new key = %q", plan.Keys[0].Filename)
	}
	for _, h := range plan.Hosts {
		for _, id := range h.IdentityKeyIDs {
			if id == existing.ID {
				return
			}
		}
	}
	t.Fatal("imported host was not linked to the existing key")
}

func TestImportComplexConfigWarns(t *testing.T) {
	dir := t.TempDir()
	m := testManager(t, dir)
	config := "Include other.conf\nMatch host foo\n    User x\nHost test\n    HostName test.example.com\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	scan, err := m.Scan(vault.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Warnings) == 0 {
		t.Fatal("expected warnings for Include/Match")
	}
	// The Host after Match is still parsed as a normal entry.
	found := false
	for _, item := range scan.Items {
		if item.Kind == "host" && item.Patterns[0] == "test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("host not found: %#v", scan.Items)
	}
}
