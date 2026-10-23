package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

type keyView struct {
	ID          string           `json:"id"`
	Alias       string           `json:"alias"`
	Filename    string           `json:"filename"`
	Tags        []string         `json:"tags"`
	Kind        string           `json:"kind"`
	Comment     string           `json:"comment"`
	Fingerprint string           `json:"fingerprint"`
	PublicKey   string           `json:"publicKey"`
	Certificate string           `json:"certificate"`
	HasPrivate  bool             `json:"hasPrivate"`
	HasPublic   bool             `json:"hasPublic"`
	HasCert     bool             `json:"hasCert"`
	CreatedAt   time.Time        `json:"createdAt"`
	UpdatedAt   time.Time        `json:"updatedAt"`
	Status      sshutil.Status   `json:"status"`
	Info        *sshutil.KeyInfo `json:"info,omitempty"`
	InfoError   string           `json:"infoError,omitempty"`
}

type hostView struct {
	ID             string         `json:"id"`
	Patterns       []string       `json:"patterns"`
	HostName       string         `json:"hostname"`
	User           string         `json:"user"`
	Port           int            `json:"port"`
	IdentityKeyIDs []string       `json:"identityKeyIds"`
	Options        []vault.Option `json:"options"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	Status         sshutil.Status `json:"status"`
	SSHCommand     string         `json:"sshCommand"`
	SSHCommandFull string         `json:"sshCommandFull"`
}

type fileView struct {
	ID          string         `json:"id"`
	Filename    string         `json:"filename"`
	Encoding    string         `json:"encoding"`
	Mode        uint32         `json:"mode"`
	Description string         `json:"description"`
	Tags        []string       `json:"tags"`
	Size        int            `json:"size"`
	Sensitive   bool           `json:"sensitive"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	Status      sshutil.Status `json:"status"`
}

type vaultInfo struct {
	Path      string    `json:"path"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type bootstrapResponse struct {
	Vault            vaultInfo  `json:"vault"`
	Keys             []keyView  `json:"keys"`
	Hosts            []hostView `json:"hosts"`
	Files            []fileView `json:"files"`
	InternalFiles    []string   `json:"internalFiles"`
	Tags             []string   `json:"tags"`
	SSHDir           string     `json:"sshDir"`
	Locked           bool       `json:"locked"`
	LockAfterSeconds int        `json:"lockAfterSeconds"`
	Version          string     `json:"version"`
	ConfigWarnings   []string   `json:"configWarnings"`
	ConfigError      string     `json:"configError,omitempty"`
}

func (a *App) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	statuses, cfgErr := a.ssh.HostStatuses(snap.Hosts, snap.Keys)
	configError := ""
	var warnings []string
	if cfgErr != nil {
		configError = cfgErr.Error()
		for _, h := range snap.Hosts {
			statuses[h.ID] = sshutil.Status{State: sshutil.StateBlocked, Message: cfgErr.Error()}
		}
	} else {
		// Only warn about hosts that are actually present in the managed block.
		// Imported-but-not-deployed hosts do not collide with anything yet.
		var deployedHosts []*vault.Host
		for _, h := range snap.Hosts {
			st := statuses[h.ID]
			if st.State == sshutil.StateDeployed || st.State == sshutil.StateDrift {
				deployedHosts = append(deployedHosts, h)
			}
		}
		warnings, _ = a.ssh.ConfigWarnings(deployedHosts)
	}

	keysByID := map[string]*vault.Key{}
	keys := make([]keyView, 0, len(snap.Keys))
	for _, k := range snap.Keys {
		keysByID[k.ID] = k
		keys = append(keys, a.makeKeyView(k))
	}
	hosts := make([]hostView, 0, len(snap.Hosts))
	for _, h := range snap.Hosts {
		hosts = append(hosts, a.makeHostView(h, keysByID, statuses[h.ID]))
	}
	files := make([]fileView, 0, len(snap.Files))
	internalFiles := []string{}
	for _, f := range snap.Files {
		if a.ssh.IsInternalFilename(f.Filename) {
			internalFiles = append(internalFiles, f.Filename)
			continue
		}
		files = append(files, makeFileView(f, a.ssh.FileStatus(f)))
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, bootstrapResponse{
		Vault: vaultInfo{
			Path:      a.currentVaultPath(),
			Revision:  snap.Revision,
			CreatedAt: snap.CreatedAt,
			UpdatedAt: snap.UpdatedAt,
		},
		Keys:             keys,
		Hosts:            hosts,
		Files:            files,
		InternalFiles:    internalFiles,
		Tags:             snap.AllTags(),
		SSHDir:           a.sshDir,
		Locked:           false,
		LockAfterSeconds: int(a.lockAfter.Seconds()),
		Version:          a.version,
		ConfigWarnings:   warnings,
		ConfigError:      configError,
	})
}

func (a *App) makeKeyView(k *vault.Key) keyView {
	v := keyView{
		ID:          k.ID,
		Alias:       k.Alias,
		Filename:    k.Filename,
		Tags:        append([]string(nil), k.Tags...),
		Kind:        k.Kind,
		Comment:     k.Comment,
		Fingerprint: k.Fingerprint,
		PublicKey:   k.PublicKey,
		Certificate: k.Certificate,
		HasPrivate:  k.PrivateKey != "",
		HasPublic:   k.PublicKey != "",
		HasCert:     k.Certificate != "",
		CreatedAt:   k.CreatedAt,
		UpdatedAt:   k.UpdatedAt,
		Status:      a.ssh.KeyStatus(k),
	}
	if info, err := sshutil.Inspect(k); err == nil {
		v.Info = &info
	} else {
		v.InfoError = err.Error()
	}
	return v
}

func (a *App) makeHostView(h *vault.Host, keysByID map[string]*vault.Key, status sshutil.Status) hostView {
	short, full := a.hostCommands(h, keysByID)
	return hostView{
		ID:             h.ID,
		Patterns:       append([]string(nil), h.Patterns...),
		HostName:       h.HostName,
		User:           h.User,
		Port:           h.Port,
		IdentityKeyIDs: append([]string(nil), h.IdentityKeyIDs...),
		Options:        append([]vault.Option(nil), h.Options...),
		CreatedAt:      h.CreatedAt,
		UpdatedAt:      h.UpdatedAt,
		Status:         status,
		SSHCommand:     short,
		SSHCommandFull: full,
	}
}

func (a *App) hostCommands(h *vault.Host, keysByID map[string]*vault.Key) (string, string) {
	alias := ""
	for _, p := range h.Patterns {
		if !strings.ContainsAny(p, "*?![") {
			alias = p
			break
		}
	}
	if alias == "" && h.HostName != "" {
		alias = h.HostName
	}
	if alias == "" && len(h.Patterns) > 0 {
		alias = h.Patterns[0]
	}
	short := "ssh " + alias
	target := h.HostName
	if target == "" {
		target = alias
	}
	if h.User != "" {
		target = h.User + "@" + target
	}
	full := "ssh"
	if h.Port > 0 && h.Port != 22 {
		full += fmt.Sprintf(" -p %d", h.Port)
	}
	for _, id := range h.IdentityKeyIDs {
		if k := keysByID[id]; k != nil {
			full += " -i " + a.ssh.DisplayPath(k.Filename)
			break
		}
	}
	full += " " + target
	return short, full
}

func makeFileView(f *vault.File, status sshutil.Status) fileView {
	size := len(f.Content)
	if f.Encoding == vault.EncodingBase64 {
		if b, err := f.ContentBytes(); err == nil {
			size = len(b)
		}
	}
	return fileView{
		ID:          f.ID,
		Filename:    f.Filename,
		Encoding:    f.Encoding,
		Mode:        f.Mode,
		Description: f.Description,
		Tags:        append([]string(nil), f.Tags...),
		Size:        size,
		Sensitive:   sensitiveFile(f.Filename),
		CreatedAt:   f.CreatedAt,
		UpdatedAt:   f.UpdatedAt,
		Status:      status,
	}
}

func sensitiveFile(name string) bool {
	switch strings.ToLower(name) {
	case "authorized_keys", "authorized_keys2", "known_hosts", "known_hosts.old", "rc", "environment":
		return true
	}
	return false
}

func (a *App) keyNameTaken(v *vault.Vault, name string) bool {
	if v.KeyByFilename(name) != nil || v.FileByFilename(name) != nil {
		return true
	}
	for _, k := range v.Keys {
		if strings.EqualFold(k.Filename+".pub", name) || strings.EqualFold(k.Filename+"-cert.pub", name) {
			return true
		}
	}
	return false
}

func (a *App) uniqueKeyFilename(v *vault.Vault, requested, alias string) (string, error) {
	name := strings.TrimSpace(requested)
	if name == "" {
		base := sanitizeAlias(alias)
		if base == "" {
			base = "key"
		}
		name = "id_" + base
		candidate := name
		for i := 2; a.keyNameTaken(v, candidate); i++ {
			candidate = fmt.Sprintf("%s-%d", name, i)
		}
		name = candidate
	}
	if err := vault.CheckFilename(name, true); err != nil {
		return "", err
	}
	if a.keyNameTaken(v, name) {
		return "", fmt.Errorf("filename %q is already in use", name)
	}
	return name, nil
}

func sanitizeAlias(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func (a *App) uniqueFileName(v *vault.Vault, requested string) (string, error) {
	name := strings.TrimSpace(requested)
	if name == "" {
		return "", fmt.Errorf("filename is required")
	}
	if err := vault.CheckFilename(name, false); err != nil {
		return "", err
	}
	if v.KeyByFilename(name) != nil || v.FileByFilename(name) != nil {
		return "", fmt.Errorf("filename %q is already in use", name)
	}
	for _, k := range v.Keys {
		if strings.EqualFold(k.Filename+".pub", name) || strings.EqualFold(k.Filename+"-cert.pub", name) {
			return "", fmt.Errorf("filename %q is already in use", name)
		}
	}
	return name, nil
}

func splitPatterns(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
