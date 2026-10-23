package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

type generateRequest struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
	Comment   string `json:"comment"`
}

type keyRequest struct {
	Revision    int64            `json:"revision"`
	Alias       string           `json:"alias"`
	Filename    string           `json:"filename"`
	Tags        []string         `json:"tags"`
	Kind        string           `json:"kind"`
	PublicKey   string           `json:"publicKey"`
	PrivateKey  string           `json:"privateKey"`
	Certificate string           `json:"certificate"`
	Comment     string           `json:"comment"`
	Deploy      bool             `json:"deploy"`
	Generate    *generateRequest `json:"generate,omitempty"`
}

type keyContentRequest struct {
	Revision    int64    `json:"revision"`
	Alias       string   `json:"alias"`
	Filename    string   `json:"filename"`
	Tags        []string `json:"tags"`
	PublicKey   string   `json:"publicKey"`
	PrivateKey  string   `json:"privateKey"`
	Certificate string   `json:"certificate"`
	Comment     string   `json:"comment"`
	Kind        string   `json:"kind"`
	Force       bool     `json:"force"`
}

func validKind(kind string) bool {
	return kind == vault.KeyKindKeypair || kind == vault.KeyKindCertificate || kind == vault.KeyKindPublic
}

func (a *App) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	var req keyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	alias := strings.TrimSpace(req.Alias)
	if alias == "" {
		writeError(w, http.StatusBadRequest, "validation", "alias is required", nil)
		return
	}
	if len(alias) > 128 || strings.ContainsAny(alias, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "validation", "invalid alias", nil)
		return
	}
	comment := strings.TrimSpace(req.Comment)
	if comment == "" {
		comment = alias
	}
	if req.Generate != nil {
		priv, pub, _, err := sshutil.Generate(req.Generate.Algorithm, req.Generate.Bits, comment)
		if err != nil {
			writeError(w, http.StatusBadRequest, "generate_failed", err.Error(), nil)
			return
		}
		req.PrivateKey = priv
		req.PublicKey = pub
		req.Certificate = ""
	}
	if strings.TrimSpace(req.PublicKey) == "" && strings.TrimSpace(req.PrivateKey) == "" && strings.TrimSpace(req.Certificate) == "" {
		writeError(w, http.StatusBadRequest, "validation", "at least one of publicKey, privateKey or certificate is required", nil)
		return
	}
	if err := sshutil.ValidateMaterial(req.PublicKey, req.PrivateKey, req.Certificate); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", err.Error(), nil)
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = sshutil.Kind(req.PublicKey, req.PrivateKey, req.Certificate)
	}
	if !validKind(kind) {
		writeError(w, http.StatusBadRequest, "validation", "invalid key kind", nil)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	filename, err := a.uniqueKeyFilename(snap, req.Filename, alias)
	if err != nil {
		writeError(w, http.StatusConflict, "filename", err.Error(), nil)
		return
	}
	now := time.Now().UTC()
	k := &vault.Key{
		ID:          vault.NewKeyID(),
		Alias:       alias,
		Filename:    filename,
		Tags:        req.Tags,
		Kind:        kind,
		PublicKey:   req.PublicKey,
		PrivateKey:  req.PrivateKey,
		Certificate: req.Certificate,
		Comment:     comment,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if info, ierr := sshutil.Inspect(k); ierr == nil {
		k.Fingerprint = info.Fingerprint
		if k.Comment == "" {
			k.Comment = info.Comment
		}
	}
	updated, err := a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		v.Keys = append(v.Keys, k)
		return nil
	})
	if err != nil {
		if errors.Is(err, vault.ErrRevision) {
			writeError(w, http.StatusConflict, "revision", err.Error(), nil)
			return
		}
		writeError(w, http.StatusBadRequest, "validation", err.Error(), nil)
		return
	}
	stored := updated.FindKey(k.ID)
	resp := map[string]any{}
	if req.Deploy {
		if st, derr := a.ssh.DeployKey(stored, sshutil.DeployOptions{}); derr != nil {
			resp["warning"] = "key saved, but could not be deployed: " + derr.Error()
			resp["status"] = st
		}
	}
	resp["key"] = a.makeKeyView(stored)
	writeJSON(w, http.StatusCreated, resp)
}

func (a *App) handleKeyRaw(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	k := snap.FindKey(r.PathValue("id"))
	if k == nil {
		notFound(w, "key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":    k,
		"status": a.ssh.KeyStatus(k),
	})
}

func (a *App) handleKeySecret(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	k := snap.FindKey(r.PathValue("id"))
	if k == nil {
		notFound(w, "key")
		return
	}
	var value string
	switch r.PathValue("field") {
	case "public":
		value = k.PublicKey
	case "private":
		value = k.PrivateKey
	case "certificate":
		value = k.Certificate
	case "fingerprint":
		value = k.Fingerprint
	default:
		writeError(w, http.StatusBadRequest, "field", "unknown key field", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"field": r.PathValue("field"), "value": value})
}

func (a *App) handleKeyUpdate(w http.ResponseWriter, r *http.Request) {
	var req keyContentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.PublicKey) == "" && strings.TrimSpace(req.PrivateKey) == "" && strings.TrimSpace(req.Certificate) == "" {
		writeError(w, http.StatusBadRequest, "validation", "at least one of publicKey, privateKey or certificate is required", nil)
		return
	}
	if err := sshutil.ValidateMaterial(req.PublicKey, req.PrivateKey, req.Certificate); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", err.Error(), nil)
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = sshutil.Kind(req.PublicKey, req.PrivateKey, req.Certificate)
	}
	if !validKind(kind) {
		writeError(w, http.StatusBadRequest, "validation", "invalid key kind", nil)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	old := snap.FindKey(r.PathValue("id"))
	if old == nil {
		notFound(w, "key")
		return
	}
	status := a.ssh.KeyStatus(old)
	if (status.State == sshutil.StateDrift || status.State == sshutil.StateBlocked) && !req.Force {
		conflict(w, fmt.Errorf("local files differ from the vault; confirm overwrite or adopt local changes"), status)
		return
	}
	alias := strings.TrimSpace(req.Alias)
	if alias == "" {
		alias = old.Alias
	}
	if len(alias) > 128 || strings.ContainsAny(alias, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "validation", "invalid alias", nil)
		return
	}
	filename := strings.TrimSpace(req.Filename)
	if filename == "" {
		filename = old.Filename
	}
	if filename != old.Filename {
		if status.State != sshutil.StateNotDeployed {
			writeError(w, http.StatusConflict, "deployed", "undeploy the key before renaming its file", nil)
			return
		}
		if filename, err = a.uniqueKeyFilename(snap, filename, alias); err != nil {
			writeError(w, http.StatusConflict, "filename", err.Error(), nil)
			return
		}
	}
	tags := req.Tags
	if tags == nil {
		tags = old.Tags
	}
	wasDeployed := status.State != sshutil.StateNotDeployed
	updated, err := a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		k := v.FindKey(old.ID)
		if k == nil {
			return fmt.Errorf("key disappeared")
		}
		k.Alias = alias
		k.Filename = filename
		k.Tags = tags
		k.PublicKey = req.PublicKey
		k.PrivateKey = req.PrivateKey
		k.Certificate = req.Certificate
		k.Kind = kind
		k.Comment = strings.TrimSpace(req.Comment)
		if info, ierr := sshutil.Inspect(k); ierr == nil {
			k.Fingerprint = info.Fingerprint
			if k.Comment == "" {
				k.Comment = info.Comment
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, vault.ErrRevision) {
			writeError(w, http.StatusConflict, "revision", err.Error(), nil)
			return
		}
		writeError(w, http.StatusBadRequest, "validation", err.Error(), nil)
		return
	}
	stored := updated.FindKey(old.ID)
	resp := map[string]any{}
	if wasDeployed {
		if st, derr := a.ssh.DeployKey(stored, sshutil.DeployOptions{Force: true}); derr != nil {
			resp["warning"] = "vault saved, but local sync failed: " + derr.Error()
			resp["status"] = st
		}
	}
	resp["key"] = a.makeKeyView(stored)
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	local := boolQuery(r, "local")
	force := boolQuery(r, "force")
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	k := snap.FindKey(r.PathValue("id"))
	if k == nil {
		notFound(w, "key")
		return
	}
	var refs []string
	for _, h := range snap.Hosts {
		for _, id := range h.IdentityKeyIDs {
			if id == k.ID {
				refs = append(refs, strings.Join(h.Patterns, " "))
				break
			}
		}
	}
	if len(refs) > 0 && !force {
		writeError(w, http.StatusConflict, "key_in_use", "this key is used by deployed or configured hosts", &apiError{Hosts: refs})
		return
	}
	if local {
		if _, derr := a.ssh.UndeployKey(k, true); derr != nil {
			internalError(w, derr)
			return
		}
	}
	_, err = a.currentStore().Update(0, func(v *vault.Vault) error {
		idx := -1
		for i, vk := range v.Keys {
			if vk.ID == k.ID {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("key disappeared")
		}
		v.Keys = append(v.Keys[:idx], v.Keys[idx+1:]...)
		for _, h := range v.Hosts {
			var ids []string
			for _, id := range h.IdentityKeyIDs {
				if id != k.ID {
					ids = append(ids, id)
				}
			}
			h.IdentityKeyIDs = ids
		}
		return nil
	})
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "hosts": refs})
}

func (a *App) handleKeyDeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Force bool `json:"force"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	k := snap.FindKey(r.PathValue("id"))
	if k == nil {
		notFound(w, "key")
		return
	}
	st, err := a.ssh.DeployKey(k, sshutil.DeployOptions{Force: req.Force})
	if err != nil {
		if sshutil.IsConflict(err) {
			conflict(w, err, st)
			return
		}
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st})
}

func (a *App) handleKeyUndeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Force bool `json:"force"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	k := snap.FindKey(r.PathValue("id"))
	if k == nil {
		notFound(w, "key")
		return
	}
	st, err := a.ssh.UndeployKey(k, req.Force)
	if err != nil {
		if sshutil.IsConflict(err) {
			conflict(w, err, st)
			return
		}
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st})
}

func (a *App) handleKeyAdoptLocal(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	old := snap.FindKey(r.PathValue("id"))
	if old == nil {
		notFound(w, "key")
		return
	}
	base := a.ssh.Path(old.Filename)
	private, err := readRegular(base)
	if err != nil {
		internalError(w, err)
		return
	}
	public, err := readRegular(base + ".pub")
	if err != nil {
		internalError(w, err)
		return
	}
	cert, err := readRegular(base + "-cert.pub")
	if err != nil {
		internalError(w, err)
		return
	}
	if private == "" && public == "" && cert == "" {
		writeError(w, http.StatusBadRequest, "no_local", "there are no local files for this key", nil)
		return
	}
	if err := sshutil.ValidateMaterial(public, private, cert); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", err.Error(), nil)
		return
	}
	candidate := *old
	candidate.PublicKey = public
	candidate.PrivateKey = private
	candidate.Certificate = cert
	candidate.Kind = sshutil.Kind(public, private, cert)
	if info, ierr := sshutil.Inspect(&candidate); ierr == nil {
		candidate.Fingerprint = info.Fingerprint
		if info.Comment != "" {
			candidate.Comment = info.Comment
		}
	}
	updated, err := a.currentStore().Update(0, func(v *vault.Vault) error {
		k := v.FindKey(old.ID)
		if k == nil {
			return fmt.Errorf("key disappeared")
		}
		k.PublicKey = candidate.PublicKey
		k.PrivateKey = candidate.PrivateKey
		k.Certificate = candidate.Certificate
		k.Kind = candidate.Kind
		k.Fingerprint = candidate.Fingerprint
		k.Comment = candidate.Comment
		return nil
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": a.makeKeyView(updated.FindKey(old.ID))})
}

func (a *App) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req generateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	comment := strings.TrimSpace(req.Comment)
	if comment == "" {
		comment = "sshvault"
	}
	priv, pub, fp, err := sshutil.Generate(req.Algorithm, req.Bits, comment)
	if err != nil {
		writeError(w, http.StatusBadRequest, "generate_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"privateKey":  priv,
		"publicKey":   pub,
		"fingerprint": fp,
	})
}

func readRegular(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink; refusing to read", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
