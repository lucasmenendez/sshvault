package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

const apiPassword = "password123"

type testEnv struct {
	t      *testing.T
	server *httptest.Server
	app    *App
	store  *vault.Store
	sshDir string
	client *http.Client
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := vault.Create(filepath.Join(dir, "ssh.vault"), apiPassword)
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(dir, "ssh")
	m, err := sshutil.NewManager(sshDir)
	if err != nil {
		t.Fatal(err)
	}
	app := New(store, m, store.Path(), m.Dir, "test", 15*time.Minute)
	srv := httptest.NewServer(app.Handler())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	app.SetPort(u.Port())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{t: t, server: srv, app: app, store: store, sshDir: sshDir, client: &http.Client{Jar: jar}}
	t.Cleanup(func() {
		srv.Close()
		_ = app.Close()
		_ = store.Close()
	})
	resp, err := env.client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return env
}

func (e *testEnv) do(method, path string, body any, headers map[string]string) (int, []byte) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.server.URL+path, rdr)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, data
}

func TestAPIFlow(t *testing.T) {
	env := newTestEnv(t)

	status, data := env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
	var boot bootstrapResponse
	if err := json.Unmarshal(data, &boot); err != nil {
		t.Fatal(err)
	}
	if boot.Vault.Revision != 1 || len(boot.Keys) != 0 {
		t.Fatalf("boot = %+v", boot)
	}

	keyBody := map[string]any{
		"revision": 1, "alias": "testkey", "filename": "", "tags": []string{"test"},
		"kind": "", "publicKey": "", "privateKey": "", "certificate": "", "comment": "testkey",
		"deploy": true, "generate": map[string]any{"algorithm": "ed25519", "bits": 0, "comment": "testkey"},
	}
	status, data = env.do("POST", "/api/keys", keyBody, nil)
	if status != 201 {
		t.Fatalf("create key = %d %s", status, data)
	}
	var keyResp struct {
		Key keyView `json:"key"`
	}
	if err := json.Unmarshal(data, &keyResp); err != nil {
		t.Fatal(err)
	}
	if keyResp.Key.Status.State != "deployed" || !keyResp.Key.HasPrivate {
		t.Fatalf("key = %+v", keyResp.Key)
	}
	if _, err := os.Stat(filepath.Join(env.sshDir, "id_testkey")); err != nil {
		t.Fatal(err)
	}

	hostBody := map[string]any{
		"revision": 2, "patterns": []string{"testhost"}, "hostname": "example.com",
		"user": "deploy", "port": 2222, "identityKeyIds": []string{keyResp.Key.ID},
		"options": []map[string]string{{"name": "IdentitiesOnly", "value": "yes"}},
		"deploy":  true, "force": false,
	}
	status, data = env.do("POST", "/api/hosts", hostBody, nil)
	if status != 201 {
		t.Fatalf("create host = %d %s", status, data)
	}
	cfg, err := os.ReadFile(filepath.Join(env.sshDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "Host testhost") || !strings.Contains(string(cfg), "IdentityFile "+env.sshDir+"/id_testkey") {
		t.Fatalf("config:\n%s", cfg)
	}

	// File creation + download.
	fileBody := map[string]any{
		"revision": 3, "filename": "known_hosts", "content": "example.com ssh-ed25519 AAAA\n",
		"encoding": "utf8", "mode": 0o600, "description": "test", "tags": []string{"t"},
		"deploy": true, "force": false,
	}
	status, data = env.do("POST", "/api/files", fileBody, nil)
	if status != 201 {
		t.Fatalf("create file = %d %s", status, data)
	}
	var fileResp struct {
		File fileView `json:"file"`
	}
	if err := json.Unmarshal(data, &fileResp); err != nil {
		t.Fatal(err)
	}
	status, data = env.do("GET", "/api/files/"+fileResp.File.ID+"/download", nil, nil)
	if status != 200 || string(data) != "example.com ssh-ed25519 AAAA\n" {
		t.Fatalf("download = %d %q", status, data)
	}

	// Secrets are available only through the explicit endpoint.
	status, data = env.do("GET", "/api/keys/"+keyResp.Key.ID+"/secret/private", nil, nil)
	if status != 200 || !strings.Contains(string(data), "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("secret = %d %s", status, data)
	}

	// Config preview.
	status, data = env.do("GET", "/api/config/preview", nil, nil)
	if status != 200 || !strings.Contains(string(data), "testhost") {
		t.Fatalf("preview = %d %s", status, data)
	}

	// Import scan should see the files and flag conflicts with the vault.
	status, data = env.do("GET", "/api/import/scan", nil, nil)
	if status != 200 || !strings.Contains(string(data), "already in vault") {
		t.Fatalf("scan = %d %s", status, data)
	}
}

func TestLockUnlockAndCSRF(t *testing.T) {
	env := newTestEnv(t)

	status, _ := env.do("POST", "/api/lock", map[string]any{}, nil)
	if status != 200 {
		t.Fatalf("lock = %d", status)
	}
	status, _ = env.do("GET", "/api/bootstrap", nil, nil)
	if status != http.StatusLocked {
		t.Fatalf("bootstrap while locked = %d", status)
	}
	status, data := env.do("POST", "/api/unlock", map[string]any{"password": "wrongpassword"}, nil)
	if status != http.StatusUnauthorized || !strings.Contains(string(data), "invalid_password") {
		t.Fatalf("unlock wrong = %d %s", status, data)
	}
	status, _ = env.do("POST", "/api/unlock", map[string]any{"password": apiPassword}, nil)
	if status != 200 {
		t.Fatalf("unlock = %d", status)
	}
	status, _ = env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap after unlock = %d", status)
	}

	// Cross-site mutations are rejected.
	status, _ = env.do("POST", "/api/lock", map[string]any{}, map[string]string{"Origin": "http://evil.example"})
	if status != http.StatusForbidden {
		t.Fatalf("cross-site lock = %d", status)
	}
	status, _ = env.do("POST", "/api/lock", map[string]any{}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if status != http.StatusForbidden {
		t.Fatalf("sec-fetch cross-site = %d", status)
	}
	// Missing JSON content type.
	status, _ = env.do("POST", "/api/lock", map[string]any{}, map[string]string{"Content-Type": "text/plain"})
	if status != http.StatusUnsupportedMediaType {
		t.Fatalf("content type = %d", status)
	}
}

func TestNoSessionAndHostGuard(t *testing.T) {
	env := newTestEnv(t)
	// A fresh client without a session cookie.
	resp, err := http.Get(env.server.URL + "/api/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session = %d", resp.StatusCode)
	}

	// Wrong Host header (DNS rebinding guard).
	req, err := http.NewRequest("GET", env.server.URL+"/api/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example:1234"
	resp, err = env.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad host = %d", resp.StatusCode)
	}
}

func TestDuplicateAPI(t *testing.T) {
	env := newTestEnv(t)
	if err := os.MkdirAll(env.sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.sshDir, "config"), []byte("Host dupe\n    User old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, data := env.do("POST", "/api/hosts", map[string]any{
		"revision": 1, "patterns": []string{"dupe"}, "hostname": "dupe.example.com",
		"user": "new", "port": 22, "identityKeyIds": []string{}, "options": []any{},
		"deploy": true, "force": false,
	}, nil)
	if status != 201 {
		t.Fatalf("create host = %d %s", status, data)
	}
	status, data = env.do("GET", "/api/config/duplicates", nil, nil)
	if status != 200 {
		t.Fatalf("duplicates = %d %s", status, data)
	}
	var report sshutil.DuplicateReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Items) != 1 || len(report.Items[0].Patterns) != 1 || report.Items[0].Patterns[0] != "dupe" {
		t.Fatalf("report = %#v", report)
	}
	status, data = env.do("POST", "/api/config/duplicates/resolve", map[string]any{
		"configHash": report.ConfigHash,
		"id":         report.Items[0].ID,
		"action":     sshutil.DuplicateActionComment,
	}, nil)
	if status != 200 {
		t.Fatalf("resolve = %d %s", status, data)
	}
	var next sshutil.DuplicateReport
	if err := json.Unmarshal(data, &next); err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 0 {
		t.Fatalf("remaining = %#v", next.Items)
	}
	cfg, err := os.ReadFile(filepath.Join(env.sshDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "# Host dupe") || !strings.Contains(string(cfg), "Host dupe\n") {
		t.Fatalf("config after comment:\n%s", cfg)
	}
	status, data = env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
	var boot bootstrapResponse
	if err := json.Unmarshal(data, &boot); err != nil {
		t.Fatal(err)
	}
	if len(boot.ConfigWarnings) != 0 {
		t.Fatalf("warnings = %#v", boot.ConfigWarnings)
	}
}

func TestInternalFilesHiddenAndCleaned(t *testing.T) {
	env := newTestEnv(t)
	status, data := env.do("POST", "/api/files", map[string]any{
		"revision": 1, "filename": "known_hosts", "content": "example.com ssh-ed25519 AAAA\n",
		"encoding": "utf8", "mode": 0o600, "description": "", "tags": []string{},
		"deploy": false, "force": false,
	}, nil)
	if status != 201 {
		t.Fatalf("create file = %d %s", status, data)
	}
	now := time.Now().UTC()
	if _, err := env.store.Update(0, func(v *vault.Vault) error {
		v.Files = append(v.Files,
			&vault.File{ID: vault.NewFileID(), Filename: "ssh.vault", Encoding: vault.EncodingUTF8, Content: "x", Mode: 0o600, CreatedAt: now, UpdatedAt: now},
			&vault.File{ID: vault.NewFileID(), Filename: "foo.vault.notes", Encoding: vault.EncodingUTF8, Content: "y", Mode: 0o600, CreatedAt: now, UpdatedAt: now},
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(env.sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.sshDir, "ssh.vault"), []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, data = env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
	var boot bootstrapResponse
	if err := json.Unmarshal(data, &boot); err != nil {
		t.Fatal(err)
	}
	if len(boot.Files) != 1 || boot.Files[0].Filename != "known_hosts" {
		t.Fatalf("visible files = %#v", boot.Files)
	}
	if len(boot.InternalFiles) != 2 {
		t.Fatalf("internal files = %#v", boot.InternalFiles)
	}

	status, data = env.do("POST", "/api/files/cleanup-internal", map[string]any{"revision": boot.Vault.Revision}, nil)
	if status != 200 {
		t.Fatalf("cleanup = %d %s", status, data)
	}
	var cleanup struct {
		Removed []string `json:"removed"`
	}
	if err := json.Unmarshal(data, &cleanup); err != nil {
		t.Fatal(err)
	}
	if len(cleanup.Removed) != 2 {
		t.Fatalf("removed = %#v", cleanup.Removed)
	}
	if _, err := os.Stat(filepath.Join(env.sshDir, "ssh.vault")); err != nil {
		t.Fatalf("cleanup should not delete disk files: %v", err)
	}
	status, data = env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
	if err := json.Unmarshal(data, &boot); err != nil {
		t.Fatal(err)
	}
	if len(boot.InternalFiles) != 0 || len(boot.Files) != 1 {
		t.Fatalf("after cleanup files=%#v internal=%#v", boot.Files, boot.InternalFiles)
	}

	// Creating a File with an internal name is rejected.
	status, data = env.do("POST", "/api/files", map[string]any{
		"revision": boot.Vault.Revision, "filename": "another.vault.notes", "content": "x",
		"encoding": "utf8", "mode": 0o600, "description": "", "tags": []string{},
		"deploy": false, "force": false,
	}, nil)
	if status != http.StatusBadRequest || !strings.Contains(string(data), "internal_name") {
		t.Fatalf("internal file creation = %d %s", status, data)
	}
}

func TestUnifiedKeyUpdate(t *testing.T) {
	env := newTestEnv(t)
	status, data := env.do("POST", "/api/keys", map[string]any{
		"revision": 1, "alias": "old", "filename": "", "tags": []string{"a"},
		"kind": "", "publicKey": "", "privateKey": "", "certificate": "", "comment": "old",
		"deploy": false, "generate": map[string]any{"algorithm": "ed25519", "bits": 0, "comment": "old"},
	}, nil)
	if status != 201 {
		t.Fatalf("create = %d %s", status, data)
	}
	var created struct {
		Key keyView `json:"key"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	status, data = env.do("GET", "/api/keys/"+created.Key.ID, nil, nil)
	if status != 200 {
		t.Fatalf("raw = %d %s", status, data)
	}
	var raw struct {
		Key vault.Key `json:"key"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	status, data = env.do("PATCH", "/api/keys/"+created.Key.ID, map[string]any{
		"revision": 2, "alias": "new", "filename": "id_new", "tags": []string{"b"},
		"publicKey": raw.Key.PublicKey, "privateKey": raw.Key.PrivateKey,
		"certificate": "", "comment": "new comment", "kind": "", "force": false,
	}, nil)
	if status != 200 {
		t.Fatalf("update = %d %s", status, data)
	}
	var updated struct {
		Key keyView `json:"key"`
	}
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Key.Alias != "new" || updated.Key.Filename != "id_new" || len(updated.Key.Tags) != 1 || updated.Key.Tags[0] != "b" {
		t.Fatalf("updated = %+v", updated.Key)
	}
	status, data = env.do("POST", "/api/keys/"+created.Key.ID+"/deploy", map[string]any{"force": false}, nil)
	if status != 200 {
		t.Fatalf("deploy = %d %s", status, data)
	}
	status, data = env.do("PATCH", "/api/keys/"+created.Key.ID, map[string]any{
		"revision": 3, "alias": "new", "filename": "id_other", "tags": []string{"b"},
		"publicKey": raw.Key.PublicKey, "privateKey": raw.Key.PrivateKey,
		"certificate": "", "comment": "new comment", "kind": "", "force": false,
	}, nil)
	if status != http.StatusConflict || !strings.Contains(string(data), "\"deployed\"") {
		t.Fatalf("rename while deployed = %d %s", status, data)
	}
}

func TestConfigWarningsOnlyForDeployedHosts(t *testing.T) {
	env := newTestEnv(t)
	if err := os.MkdirAll(env.sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.sshDir, "config"), []byte("Host dupe\n    User old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, data := env.do("POST", "/api/hosts", map[string]any{
		"revision": 1, "patterns": []string{"dupe"}, "hostname": "dupe.example.com",
		"user": "new", "port": 22, "identityKeyIds": []string{}, "options": []any{},
		"deploy": false, "force": false,
	}, nil)
	if status != 201 {
		t.Fatalf("create host = %d %s", status, data)
	}
	var created struct {
		Host hostView `json:"host"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	status, data = env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
	var boot bootstrapResponse
	if err := json.Unmarshal(data, &boot); err != nil {
		t.Fatal(err)
	}
	if len(boot.ConfigWarnings) != 0 {
		t.Fatalf("unexpected warnings for a non-deployed host: %#v", boot.ConfigWarnings)
	}

	status, data = env.do("POST", "/api/hosts/"+created.Host.ID+"/deploy", map[string]any{}, nil)
	if status != 200 {
		t.Fatalf("deploy host = %d %s", status, data)
	}
	status, data = env.do("GET", "/api/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
	if err := json.Unmarshal(data, &boot); err != nil {
		t.Fatal(err)
	}
	if len(boot.ConfigWarnings) == 0 || !strings.Contains(strings.Join(boot.ConfigWarnings, " "), "dupe") {
		t.Fatalf("expected a collision warning, got %#v", boot.ConfigWarnings)
	}
}

func TestRevisionConflictAndPasswordChange(t *testing.T) {
	env := newTestEnv(t)
	priv, pub, _, err := sshutil.Generate("ed25519", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"revision": 1, "alias": "a", "filename": "id_a", "tags": []string{},
		"kind": "keypair", "publicKey": pub,
		"privateKey": priv, "certificate": "", "comment": "", "deploy": false,
	}
	status, data := env.do("POST", "/api/keys", body, nil)
	if status != 201 {
		t.Fatalf("create = %d %s", status, data)
	}
	status, _ = env.do("POST", "/api/keys", body, nil) // revision is now 2
	if status != http.StatusConflict {
		t.Fatalf("stale revision = %d", status)
	}

	status, data = env.do("POST", "/api/password", map[string]any{"current": apiPassword, "next": "newpassword123"}, nil)
	if status != 200 {
		t.Fatalf("password change = %d %s", status, data)
	}
}

func newLockedTestEnv(t *testing.T, path string, exists bool) *testEnv {
	t.Helper()
	if exists {
		s, err := vault.Create(path, apiPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	store, err := vault.OpenLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(filepath.Dir(path), "ssh")
	m, err := sshutil.NewManager(sshDir)
	if err != nil {
		t.Fatal(err)
	}
	app := New(store, m, store.Path(), m.Dir, "test", 15*time.Minute)
	srv := httptest.NewServer(app.Handler())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	app.SetPort(u.Port())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{t: t, server: srv, app: app, store: store, sshDir: sshDir, client: &http.Client{Jar: jar}}
	t.Cleanup(func() {
		srv.Close()
		_ = app.Close()
		_ = store.Close()
	})
	resp, err := env.client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return env
}

func TestLockedStartupUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.vault")
	env := newLockedTestEnv(t, path, true)

	status, data := env.do("GET", "/api/session", nil, nil)
	if status != 200 {
		t.Fatalf("session = %d %s", status, data)
	}
	var session struct {
		Locked       bool `json:"locked"`
		NeedsSetup   bool `json:"needsSetup"`
		CanPickVault bool `json:"canPickVault"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	if !session.Locked || session.NeedsSetup || session.CanPickVault {
		t.Fatalf("session = %#v", session)
	}
	if status, _ := env.do("GET", "/api/bootstrap", nil, nil); status != http.StatusLocked {
		t.Fatalf("bootstrap locked = %d", status)
	}
	if status, data := env.do("POST", "/api/unlock", map[string]any{"password": "wrongpass"}, nil); status != http.StatusUnauthorized {
		t.Fatalf("wrong unlock = %d %s", status, data)
	}
	if status, data := env.do("POST", "/api/unlock", map[string]any{"password": apiPassword}, nil); status != 200 {
		t.Fatalf("unlock = %d %s", status, data)
	}
	if status, data := env.do("GET", "/api/bootstrap", nil, nil); status != 200 {
		t.Fatalf("bootstrap = %d %s", status, data)
	}
}

func TestSetupAndOpenExistingVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.vault")
	env := newLockedTestEnv(t, path, false)

	status, data := env.do("GET", "/api/session", nil, nil)
	if status != 200 || !strings.Contains(string(data), `"needsSetup":true`) {
		t.Fatalf("session = %d %s", status, data)
	}
	if status, _ := env.do("POST", "/api/setup", map[string]any{"password": "short"}, nil); status != http.StatusBadRequest {
		t.Fatalf("weak setup = %d", status)
	}
	if status, data := env.do("POST", "/api/setup", map[string]any{"password": apiPassword}, nil); status != 200 {
		t.Fatalf("setup = %d %s", status, data)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if status, data := env.do("GET", "/api/bootstrap", nil, nil); status != 200 {
		t.Fatalf("bootstrap after setup = %d %s", status, data)
	}

	other := filepath.Join(dir, "other.vault")
	s, err := vault.Create(other, apiPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if status, data := env.do("POST", "/api/vault/open", map[string]any{"path": other}, nil); status != 200 {
		t.Fatalf("open existing = %d %s", status, data)
	}
	// The previous store must have released its process lock.
	oldStore, err := vault.Open(path, apiPassword)
	if err != nil {
		t.Fatalf("previous vault lock was not released: %v", err)
	}
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}
	if status, data := env.do("GET", "/api/session", nil, nil); status != 200 || !strings.Contains(string(data), `"locked":true`) {
		t.Fatalf("session after switch = %d %s", status, data)
	}
	if status, _ := env.do("GET", "/api/bootstrap", nil, nil); status != http.StatusLocked {
		t.Fatalf("bootstrap after switch = %d", status)
	}
	if status, data := env.do("POST", "/api/unlock", map[string]any{"password": apiPassword}, nil); status != 200 {
		t.Fatalf("unlock switched = %d %s", status, data)
	}
	if status, data := env.do("POST", "/api/vault/open", map[string]any{"path": filepath.Join(dir, "missing.vault")}, nil); status != http.StatusNotFound {
		t.Fatalf("open missing = %d %s", status, data)
	}
}

func TestVaultPickerEndpoint(t *testing.T) {
	env := newTestEnv(t)
	status, data := env.do("GET", "/api/session", nil, nil)
	if status != 200 || !strings.Contains(string(data), `"canPickVault":false`) {
		t.Fatalf("session without picker = %d %s", status, data)
	}
	want := filepath.Join(t.TempDir(), "picked.vault")
	env.app.SetVaultPicker(func() (string, error) { return want, nil })
	status, data = env.do("GET", "/api/session", nil, nil)
	if status != 200 || !strings.Contains(string(data), `"canPickVault":true`) {
		t.Fatalf("session with picker = %d %s", status, data)
	}
	status, data = env.do("POST", "/api/vault/pick", map[string]any{}, nil)
	if status != 200 || !strings.Contains(string(data), want) {
		t.Fatalf("pick = %d %s", status, data)
	}
}
