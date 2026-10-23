package vault

import (
	"strings"
	"testing"
	"time"
)

func baseVault() *Vault {
	v := NewVault()
	v.Keys = []*Key{{
		ID:         NewKeyID(),
		Alias:      "test",
		Filename:   "id_test",
		Kind:       KeyKindKeypair,
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA test\n",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}}
	v.Hosts = []*Host{{
		ID:             NewHostID(),
		Patterns:       []string{"example"},
		HostName:       "example.com",
		User:           "deploy",
		Port:           2222,
		IdentityKeyIDs: []string{v.Keys[0].ID},
		Options:        []Option{{Name: "IdentitiesOnly", Value: "yes"}},
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}}
	return v
}

func TestVaultValidateOK(t *testing.T) {
	v := baseVault()
	v.Files = []*File{{
		ID:       NewFileID(),
		Filename: "known_hosts",
		Encoding: EncodingUTF8,
		Content:  "example.com ssh-ed25519 AAAA\n",
		Mode:     0o600,
	}}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFilenameCollisions(t *testing.T) {
	v := baseVault()
	v.Files = []*File{{
		ID:       NewFileID(),
		Filename: "id_test.pub",
		Encoding: EncodingUTF8,
		Content:  "x",
		Mode:     0o600,
	}}
	if err := v.Validate(); err == nil {
		t.Fatal("expected a collision between key derived name and file")
	}
}

func TestReservedFilenames(t *testing.T) {
	cases := []struct {
		name  string
		isKey bool
		ok    bool
	}{
		{"config", false, false},
		{"config.d", false, false},
		{"authorized_keys", true, false},
		{"known_hosts", true, false},
		{"id_test.pub", true, false},
		{"id_test-cert.pub", true, false},
		{"known_hosts", false, true},
		{"authorized_keys", false, true},
		{"id_test", true, true},
		{"foo.pub", false, true},
	}
	for _, c := range cases {
		err := CheckFilename(c.name, c.isKey)
		if c.ok && err != nil {
			t.Errorf("%q key=%v: unexpected error %v", c.name, c.isKey, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q key=%v: expected error", c.name, c.isKey)
		}
	}
}

func TestDuplicateHostPatterns(t *testing.T) {
	v := baseVault()
	v.Hosts = append(v.Hosts, &Host{
		ID:        NewHostID(),
		Patterns:  []string{"EXAMPLE"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err := v.Validate(); err == nil {
		t.Fatal("expected duplicate host pattern error")
	}
}

func TestHostInvalidPattern(t *testing.T) {
	v := baseVault()
	v.Hosts[0].Patterns = []string{"bad pattern"}
	if err := v.Validate(); err == nil {
		t.Fatal("expected invalid pattern error")
	}
}

func TestHostUnknownKey(t *testing.T) {
	v := baseVault()
	v.Hosts[0].IdentityKeyIDs = []string{NewKeyID()}
	if err := v.Validate(); err == nil {
		t.Fatal("expected unknown key error")
	}
}

func TestHostForbiddenOption(t *testing.T) {
	v := baseVault()
	v.Hosts[0].Options = []Option{{Name: "HostName", Value: "x"}}
	if err := v.Validate(); err == nil {
		t.Fatal("expected forbidden option error")
	}
}

func TestFileModesAndBase64(t *testing.T) {
	v := baseVault()
	v.Files = []*File{{
		ID:       NewFileID(),
		Filename: "binary",
		Encoding: EncodingBase64,
		Content:  "AAEC",
		Mode:     0o755,
	}}
	if err := v.Validate(); err == nil {
		t.Fatal("expected invalid mode error")
	}
	v.Files[0].Mode = 0o600
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	v.Files[0].Content = "not base64!"
	if err := v.Validate(); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("expected base64 error, got %v", err)
	}
}

func TestNormalizeTagsAndPatterns(t *testing.T) {
	v := baseVault()
	v.Keys[0].Tags = []string{" Work ", "work", "git", ""}
	v.Hosts[0].Patterns = []string{"foo, bar", "foo"}
	v.Normalize()
	if got := v.Keys[0].Tags; len(got) != 2 || got[0] != "Work" || got[1] != "git" {
		t.Fatalf("tags = %#v", got)
	}
	if got := v.Hosts[0].Patterns; len(got) != 2 || got[0] != "foo" || got[1] != "bar" {
		t.Fatalf("patterns = %#v", got)
	}
}

func TestAllTags(t *testing.T) {
	v := baseVault()
	v.Keys[0].Tags = []string{"b", "a"}
	v.Files = []*File{{ID: NewFileID(), Filename: "x", Encoding: EncodingUTF8, Content: "", Mode: 0o600, Tags: []string{"c", "a"}}}
	tags := v.AllTags()
	if len(tags) != 3 {
		t.Fatalf("tags = %#v", tags)
	}
}
