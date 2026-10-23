package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

type fileRequest struct {
	Revision    int64    `json:"revision"`
	Filename    string   `json:"filename"`
	Content     string   `json:"content"`
	Encoding    string   `json:"encoding"`
	Mode        uint32   `json:"mode"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Deploy      bool     `json:"deploy"`
	Force       bool     `json:"force"`
}

func normalizeFileContent(content, encoding string) (string, string, error) {
	if encoding == "" {
		encoding = vault.EncodingUTF8
	}
	switch encoding {
	case vault.EncodingUTF8:
		if len(content) > vault.MaxFileContent {
			return "", "", fmt.Errorf("file is too large (max %d bytes)", vault.MaxFileContent)
		}
		return content, encoding, nil
	case vault.EncodingBase64:
		b, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return "", "", fmt.Errorf("invalid base64 content")
		}
		if len(b) > vault.MaxFileContent {
			return "", "", fmt.Errorf("file is too large (max %d bytes)", vault.MaxFileContent)
		}
		return content, encoding, nil
	default:
		return "", "", fmt.Errorf("invalid encoding %q", encoding)
	}
}

func (a *App) handleFileCreate(w http.ResponseWriter, r *http.Request) {
	var req fileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	content, encoding, err := normalizeFileContent(req.Content, req.Encoding)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error(), nil)
		return
	}
	mode := req.Mode
	if mode == 0 {
		mode = 0o600
	}
	if mode != 0o600 && mode != 0o640 && mode != 0o644 {
		writeError(w, http.StatusBadRequest, "validation", "mode must be 0600, 0640 or 0644", nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	filename, err := a.uniqueFileName(snap, req.Filename)
	if err != nil {
		writeError(w, http.StatusConflict, "filename", err.Error(), nil)
		return
	}
	if a.ssh.IsInternalFilename(filename) {
		writeError(w, http.StatusBadRequest, "internal_name", "this filename is reserved for sshvault internals", nil)
		return
	}
	now := time.Now().UTC()
	f := &vault.File{
		ID:          vault.NewFileID(),
		Filename:    filename,
		Encoding:    encoding,
		Content:     content,
		Mode:        mode,
		Description: strings.TrimSpace(req.Description),
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	updated, err := a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		v.Files = append(v.Files, f)
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
	stored := updated.FindFile(f.ID)
	resp := map[string]any{}
	if req.Deploy {
		if st, derr := a.ssh.DeployFile(stored, sshutil.DeployOptions{}); derr != nil {
			resp["warning"] = "file saved, but could not be deployed: " + derr.Error()
			resp["status"] = st
		}
	}
	resp["file"] = makeFileView(stored, a.ssh.FileStatus(stored))
	writeJSON(w, http.StatusCreated, resp)
}

func (a *App) handleFileRaw(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	f := snap.FindFile(r.PathValue("id"))
	if f == nil {
		notFound(w, "file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"file":   f,
		"status": a.ssh.FileStatus(f),
	})
}

func (a *App) handleFileUpdate(w http.ResponseWriter, r *http.Request) {
	var req fileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	content, encoding, err := normalizeFileContent(req.Content, req.Encoding)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error(), nil)
		return
	}
	mode := req.Mode
	if mode == 0 {
		mode = 0o600
	}
	if mode != 0o600 && mode != 0o640 && mode != 0o644 {
		writeError(w, http.StatusBadRequest, "validation", "mode must be 0600, 0640 or 0644", nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	old := snap.FindFile(r.PathValue("id"))
	if old == nil {
		notFound(w, "file")
		return
	}
	status := a.ssh.FileStatus(old)
	if (status.State == sshutil.StateDrift || status.State == sshutil.StateBlocked) && !req.Force {
		conflict(w, fmt.Errorf("local file differs from the vault; confirm overwrite or adopt local changes"), status)
		return
	}
	filename := strings.TrimSpace(req.Filename)
	if filename == "" {
		filename = old.Filename
	}
	if filename != old.Filename {
		if status.State != sshutil.StateNotDeployed {
			writeError(w, http.StatusConflict, "deployed", "undeploy the file before renaming it", nil)
			return
		}
		if filename, err = a.uniqueFileName(snap, filename); err != nil {
			writeError(w, http.StatusConflict, "filename", err.Error(), nil)
			return
		}
	}
	if a.ssh.IsInternalFilename(filename) {
		writeError(w, http.StatusBadRequest, "internal_name", "this filename is reserved for sshvault internals", nil)
		return
	}
	wasDeployed := status.State != sshutil.StateNotDeployed
	updated, err := a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		f := v.FindFile(old.ID)
		if f == nil {
			return fmt.Errorf("file disappeared")
		}
		f.Filename = filename
		f.Encoding = encoding
		f.Content = content
		f.Mode = mode
		f.Description = strings.TrimSpace(req.Description)
		f.Tags = req.Tags
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
	stored := updated.FindFile(old.ID)
	resp := map[string]any{}
	if wasDeployed {
		if st, derr := a.ssh.DeployFile(stored, sshutil.DeployOptions{Force: true}); derr != nil {
			resp["warning"] = "vault saved, but local sync failed: " + derr.Error()
			resp["status"] = st
		}
	}
	resp["file"] = makeFileView(stored, a.ssh.FileStatus(stored))
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	local := boolQuery(r, "local")
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	f := snap.FindFile(r.PathValue("id"))
	if f == nil {
		notFound(w, "file")
		return
	}
	if local {
		if _, derr := a.ssh.UndeployFile(f, true); derr != nil {
			internalError(w, derr)
			return
		}
	}
	_, err = a.currentStore().Update(0, func(v *vault.Vault) error {
		idx := -1
		for i, vf := range v.Files {
			if vf.ID == f.ID {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("file disappeared")
		}
		v.Files = append(v.Files[:idx], v.Files[idx+1:]...)
		return nil
	})
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (a *App) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	f := snap.FindFile(r.PathValue("id"))
	if f == nil {
		notFound(w, "file")
		return
	}
	b, err := f.ContentBytes()
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", f.Filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	_, _ = w.Write(b)
}

func (a *App) handleFileDeploy(w http.ResponseWriter, r *http.Request) {
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
	f := snap.FindFile(r.PathValue("id"))
	if f == nil {
		notFound(w, "file")
		return
	}
	st, err := a.ssh.DeployFile(f, sshutil.DeployOptions{Force: req.Force})
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

func (a *App) handleFileUndeploy(w http.ResponseWriter, r *http.Request) {
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
	f := snap.FindFile(r.PathValue("id"))
	if f == nil {
		notFound(w, "file")
		return
	}
	st, err := a.ssh.UndeployFile(f, req.Force)
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

func (a *App) handleCleanupInternalFiles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision int64 `json:"revision"`
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
	var names []string
	for _, f := range snap.Files {
		if a.ssh.IsInternalFilename(f.Filename) {
			names = append(names, f.Filename)
		}
	}
	if len(names) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"removed": []string{}})
		return
	}
	_, err = a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		files := v.Files[:0]
		for _, f := range v.Files {
			if !a.ssh.IsInternalFilename(f.Filename) {
				files = append(files, f)
			}
		}
		v.Files = files
		return nil
	})
	if err != nil {
		if errors.Is(err, vault.ErrRevision) {
			writeError(w, http.StatusConflict, "revision", err.Error(), nil)
			return
		}
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": names})
}

func (a *App) handleFileAdoptLocal(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	old := snap.FindFile(r.PathValue("id"))
	if old == nil {
		notFound(w, "file")
		return
	}
	path := a.ssh.Path(old.Filename)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusBadRequest, "no_local", "the local file does not exist", nil)
			return
		}
		internalError(w, err)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		writeError(w, http.StatusBadRequest, "no_local", "the local path is not a regular file", nil)
		return
	}
	if info.Size() > vault.MaxFileContent {
		writeError(w, http.StatusBadRequest, "too_large", "the local file is too large", nil)
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		internalError(w, err)
		return
	}
	mode := uint32(info.Mode().Perm())
	if mode != 0o600 && mode != 0o640 && mode != 0o644 {
		mode = old.Mode
	}
	updated, err := a.currentStore().Update(0, func(v *vault.Vault) error {
		f := v.FindFile(old.ID)
		if f == nil {
			return fmt.Errorf("file disappeared")
		}
		f.SetContentBytes(b)
		f.Mode = mode
		return nil
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error(), nil)
		return
	}
	stored := updated.FindFile(old.ID)
	writeJSON(w, http.StatusOK, map[string]any{"file": makeFileView(stored, a.ssh.FileStatus(stored))})
}
