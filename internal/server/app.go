package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
	"sshvault/internal/web"
)

const sessionCookie = "sshvault_session"

// App serves the API and the embedded SPA.
type App struct {
	storeMu sync.RWMutex
	store   *vault.Store

	ssh       *sshutil.Manager
	vaultPath string
	sshDir    string
	version   string
	lockAfter time.Duration
	port      string
	sessionID string

	mu                 sync.Mutex
	lastActivity       time.Time
	unlockFails        int
	unlockBlockedUntil time.Time

	picker func() (string, error)
	mux    http.Handler
}

func New(store *vault.Store, manager *sshutil.Manager, vaultPath, sshDir, version string, lockAfter time.Duration) *App {
	manager.SetVaultPath(vaultPath)
	a := &App{
		store:        store,
		ssh:          manager,
		vaultPath:    vaultPath,
		sshDir:       sshDir,
		version:      version,
		lockAfter:    lockAfter,
		sessionID:    randomToken(),
		lastActivity: time.Now(),
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/session", a.handleSession)
	mux.HandleFunc("GET /api/bootstrap", a.handleBootstrap)
	mux.HandleFunc("POST /api/lock", a.handleLock)
	mux.HandleFunc("POST /api/unlock", a.handleUnlock)
	mux.HandleFunc("POST /api/password", a.handlePassword)
	mux.HandleFunc("POST /api/setup", a.handleSetup)
	mux.HandleFunc("POST /api/vault/open", a.handleOpenVault)
	mux.HandleFunc("POST /api/vault/pick", a.handlePickVault)

	mux.HandleFunc("GET /api/config/preview", a.handleConfigPreview)
	mux.HandleFunc("GET /api/config/duplicates", a.handleDuplicates)
	mux.HandleFunc("POST /api/config/duplicates/resolve", a.handleResolveDuplicate)
	mux.HandleFunc("GET /api/import/scan", a.handleImportScan)
	mux.HandleFunc("POST /api/import/apply", a.handleImportApply)

	mux.HandleFunc("GET /api/keys/{id}", a.handleKeyRaw)
	mux.HandleFunc("POST /api/keys", a.handleKeyCreate)
	mux.HandleFunc("PATCH /api/keys/{id}", a.handleKeyUpdate)
	mux.HandleFunc("DELETE /api/keys/{id}", a.handleKeyDelete)
	mux.HandleFunc("GET /api/keys/{id}/secret/{field}", a.handleKeySecret)
	mux.HandleFunc("POST /api/keys/{id}/deploy", a.handleKeyDeploy)
	mux.HandleFunc("POST /api/keys/{id}/undeploy", a.handleKeyUndeploy)
	mux.HandleFunc("POST /api/keys/{id}/adopt-local", a.handleKeyAdoptLocal)
	mux.HandleFunc("POST /api/generate", a.handleGenerate)

	mux.HandleFunc("POST /api/hosts", a.handleHostCreate)
	mux.HandleFunc("PATCH /api/hosts/{id}", a.handleHostUpdate)
	mux.HandleFunc("DELETE /api/hosts/{id}", a.handleHostDelete)
	mux.HandleFunc("POST /api/hosts/{id}/deploy", a.handleHostDeploy)
	mux.HandleFunc("POST /api/hosts/{id}/undeploy", a.handleHostUndeploy)

	mux.HandleFunc("POST /api/files", a.handleFileCreate)
	mux.HandleFunc("POST /api/files/cleanup-internal", a.handleCleanupInternalFiles)
	mux.HandleFunc("GET /api/files/{id}/raw", a.handleFileRaw)
	mux.HandleFunc("PATCH /api/files/{id}", a.handleFileUpdate)
	mux.HandleFunc("DELETE /api/files/{id}", a.handleFileDelete)
	mux.HandleFunc("GET /api/files/{id}/download", a.handleFileDownload)
	mux.HandleFunc("POST /api/files/{id}/deploy", a.handleFileDeploy)
	mux.HandleFunc("POST /api/files/{id}/undeploy", a.handleFileUndeploy)
	mux.HandleFunc("POST /api/files/{id}/adopt-local", a.handleFileAdoptLocal)

	for _, method := range []string{"GET", "POST", "PATCH", "DELETE", "PUT"} {
		mux.HandleFunc(method+" /api/", func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "not_found", "API endpoint not found", nil)
		})
	}

	mux.HandleFunc("GET /", a.handleStatic)
	for _, name := range []string{"app.js", "styles.css", "sumi.css", "icons.svg", "favicon.svg"} {
		mux.HandleFunc("GET /"+name, a.handleAsset(name))
	}
	a.mux = mux
	return a
}

func (a *App) SetPort(port string) { a.port = port }

// Close releases the currently open vault, including a vault opened through
// the web UI after startup.
func (a *App) Close() error {
	st := a.currentStore()
	if st == nil {
		return nil
	}
	return st.Close()
}

func (a *App) currentStore() *vault.Store {
	a.storeMu.RLock()
	defer a.storeMu.RUnlock()
	return a.store
}

func (a *App) currentVaultPath() string {
	a.storeMu.RLock()
	defer a.storeMu.RUnlock()
	return a.vaultPath
}

func (a *App) replaceStore(next *vault.Store) {
	a.storeMu.Lock()
	old := a.store
	a.store = next
	a.vaultPath = next.Path()
	a.storeMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	a.ssh.SetVaultPath(next.Path())
	a.mu.Lock()
	a.lastActivity = time.Now()
	a.unlockFails = 0
	a.unlockBlockedUntil = time.Time{}
	a.mu.Unlock()
}

// SetVaultPicker installs the optional native file picker used by --ui.
func (a *App) SetVaultPicker(picker func() (string, error)) {
	a.picker = picker
}

func (a *App) canPickVault() bool { return a.picker != nil }

// OpenVault switches the app to an existing vault file and leaves it locked.
func (a *App) OpenVault(path string) error {
	current := a.currentStore()
	if current.Path() == path {
		if current.NeedsSetup() {
			return vault.ErrNotFound
		}
		current.Lock()
		return nil
	}
	next, err := vault.OpenLocked(path)
	if err != nil {
		return err
	}
	if next.NeedsSetup() {
		_ = next.Close()
		return vault.ErrNotFound
	}
	a.replaceStore(next)
	return nil
}

func (a *App) Handler() http.Handler {
	return http.HandlerFunc(a.serve)
}

func (a *App) serve(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !a.validHost(r) {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") {
		if !a.validSession(r) {
			writeError(w, http.StatusUnauthorized, "no_session", "missing or invalid session cookie", nil)
			return
		}
		if isMutating(r.Method) {
			if !a.validCSRF(r) {
				writeError(w, http.StatusForbidden, "csrf", "cross-site request rejected", nil)
				return
			}
			ct := strings.ToLower(r.Header.Get("Content-Type"))
			if !strings.HasPrefix(ct, "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, "content_type", "expected application/json", nil)
				return
			}
		}
		a.checkIdle()
		if a.currentStore().IsLocked() && !lockedEndpoint(path) {
			writeError(w, http.StatusLocked, "locked", "vault is locked", nil)
			return
		}
	}
	a.mux.ServeHTTP(w, r)
}

func (a *App) validHost(r *http.Request) bool {
	if a.port == "" {
		return false
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return false
	}
	if port != a.port {
		return false
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func (a *App) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(a.sessionID)) == 1
}

func (a *App) validCSRF(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (a *App) checkIdle() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lockAfter > 0 && !a.currentStore().IsLocked() && time.Since(a.lastActivity) > a.lockAfter {
		a.currentStore().Lock()
		slog.Info("vault locked after inactivity")
	}
	if !a.currentStore().IsLocked() {
		a.lastActivity = time.Now()
	}
}

func lockedEndpoint(path string) bool {
	switch path {
	case "/api/session", "/api/unlock", "/api/setup", "/api/vault/open", "/api/vault/pick":
		return true
	default:
		return false
	}
}

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	st := a.currentStore()
	locked := st.IsLocked()
	out := map[string]any{
		"locked":       locked,
		"needsSetup":   locked && st.NeedsSetup(),
		"canPickVault": a.canPickVault(),
	}
	if !locked {
		if snap, err := st.Snapshot(); err == nil {
			out["revision"] = snap.Revision
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleLock(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.currentStore().Lock()
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"locked": true})
}

func (a *App) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.currentStore().IsLocked() {
		writeJSON(w, http.StatusOK, map[string]any{"locked": false})
		return
	}
	now := time.Now()
	if now.Before(a.unlockBlockedUntil) {
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again shortly", nil)
		return
	}
	err := a.currentStore().Unlock(req.Password)
	if err != nil {
		a.unlockFails++
		if a.unlockFails >= 5 {
			a.unlockFails = 0
			a.unlockBlockedUntil = now.Add(30 * time.Second)
		}
		if errors.Is(err, vault.ErrInvalidPassword) {
			writeError(w, http.StatusUnauthorized, "invalid_password", "invalid password", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "unlock_failed", err.Error(), nil)
		return
	}
	a.unlockFails = 0
	a.unlockBlockedUntil = time.Time{}
	a.lastActivity = now
	writeJSON(w, http.StatusOK, map[string]any{"locked": false})
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Next) < 8 {
		writeError(w, http.StatusBadRequest, "weak_password", "the new password must be at least 8 characters", nil)
		return
	}
	a.mu.Lock()
	err := a.currentStore().ChangePassword(req.Current, req.Next)
	a.mu.Unlock()
	if err != nil {
		if errors.Is(err, vault.ErrInvalidPassword) {
			writeError(w, http.StatusForbidden, "invalid_password", "current password is incorrect", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "password_change_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	st := a.currentStore()
	if !st.NeedsSetup() {
		writeError(w, http.StatusConflict, "vault_exists", "the vault already exists", nil)
		return
	}
	a.mu.Lock()
	err := st.Create(req.Password)
	if err == nil {
		a.lastActivity = time.Now()
		a.unlockFails = 0
		a.unlockBlockedUntil = time.Time{}
	}
	a.mu.Unlock()
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrWeakPassword):
			writeError(w, http.StatusBadRequest, "weak_password", err.Error(), nil)
		case errors.Is(err, vault.ErrVaultExists):
			writeError(w, http.StatusConflict, "vault_exists", "the vault already exists", nil)
		default:
			writeError(w, http.StatusInternalServerError, "setup_failed", err.Error(), nil)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"locked": false, "created": true})
}

func (a *App) handleOpenVault(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	path, err := resolveVaultPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	if err := a.OpenVault(path); err != nil {
		switch {
		case errors.Is(err, vault.ErrNotFound):
			writeError(w, http.StatusNotFound, "vault_not_found", "vault file not found", nil)
		case errors.Is(err, vault.ErrInUse):
			writeError(w, http.StatusConflict, "vault_in_use", "this vault is already open by another sshvault process", nil)
		default:
			writeError(w, http.StatusBadRequest, "open_failed", err.Error(), nil)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"locked": true, "path": path})
}

func (a *App) handlePickVault(w http.ResponseWriter, r *http.Request) {
	if a.picker == nil {
		writeError(w, http.StatusNotImplemented, "picker_unavailable", "native file picker is not available", nil)
		return
	}
	path, err := a.picker()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "picker_failed", err.Error(), nil)
		return
	}
	if strings.TrimSpace(path) == "" {
		writeJSON(w, http.StatusOK, map[string]any{"path": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path})
}

func resolveVaultPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("vault path is required")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return filepath.Abs(path)
}

func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if c, err := r.Cookie(sessionCookie); err != nil || c.Value != a.sessionID {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    a.sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	data, err := web.FS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "missing index", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

func (a *App) handleAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		switch {
		case strings.HasSuffix(name, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case strings.HasSuffix(name, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case strings.HasSuffix(name, ".svg"):
			w.Header().Set("Content-Type", "image/svg+xml")
		}
		data, err := web.FS.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("server: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type apiErrorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Hosts   []string        `json:"hosts,omitempty"`
	Status  *sshutil.Status `json:"status,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string, extra *apiError) {
	body := apiErrorBody{Error: apiError{Code: code, Message: message}}
	if extra != nil {
		if extra.Hosts != nil {
			body.Error.Hosts = extra.Hosts
		}
		if extra.Status != nil {
			body.Error.Status = extra.Status
		}
	}
	writeJSON(w, status, body)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "invalid request body: "+err.Error(), nil)
		return false
	}
	return true
}

func boolQuery(r *http.Request, name string) bool {
	switch strings.ToLower(r.URL.Query().Get(name)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func notFound(w http.ResponseWriter, what string) {
	writeError(w, http.StatusNotFound, "not_found", what+" not found", nil)
}

func locked(w http.ResponseWriter) {
	writeError(w, http.StatusLocked, "locked", "vault is locked", nil)
}

func internalError(w http.ResponseWriter, err error) {
	writeError(w, http.StatusInternalServerError, "internal", err.Error(), nil)
}

func conflict(w http.ResponseWriter, err error, st sshutil.Status) {
	extra := &apiError{Status: &st}
	writeError(w, http.StatusConflict, "conflict", err.Error(), extra)
}

func fmtPort(p int) string {
	if p <= 0 {
		return "22"
	}
	return fmt.Sprintf("%d", p)
}
