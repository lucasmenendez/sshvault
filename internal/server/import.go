package server

import (
	"errors"
	"net/http"

	"sshvault/internal/vault"
)

func (a *App) handleImportScan(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	result, err := a.ssh.Scan(snap)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleImportApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision int64    `json:"revision"`
		IDs      []string `json:"ids"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	selected := map[string]bool{}
	for _, id := range req.IDs {
		selected[id] = true
	}
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "validation", "no items selected", nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	plan, err := a.ssh.BuildImport(snap, selected)
	if err != nil {
		internalError(w, err)
		return
	}
	if len(plan.Keys) == 0 && len(plan.Hosts) == 0 && len(plan.Files) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"imported": map[string]int{"keys": 0, "hosts": 0, "files": 0},
			"warnings": plan.Warnings,
		})
		return
	}
	_, err = a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		v.Keys = append(v.Keys, plan.Keys...)
		v.Files = append(v.Files, plan.Files...)
		v.Hosts = append(v.Hosts, plan.Hosts...)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": map[string]int{
			"keys":  len(plan.Keys),
			"hosts": len(plan.Hosts),
			"files": len(plan.Files),
		},
		"warnings": plan.Warnings,
	})
}
