package server

import (
	"errors"
	"net/http"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

func (a *App) deployedHosts(snap *vault.Vault) ([]*vault.Host, map[string]sshutil.Status, error) {
	statuses, err := a.ssh.HostStatuses(snap.Hosts, snap.Keys)
	if err != nil {
		return nil, nil, err
	}
	var out []*vault.Host
	for _, h := range snap.Hosts {
		st := statuses[h.ID]
		if st.State == sshutil.StateDeployed || st.State == sshutil.StateDrift {
			out = append(out, h)
		}
	}
	return out, statuses, nil
}

func (a *App) handleDuplicates(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	hosts, _, err := a.deployedHosts(snap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config", err.Error(), nil)
		return
	}
	report, err := a.ssh.DuplicateReport(hosts, snap.Keys)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *App) handleResolveDuplicate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConfigHash string `json:"configHash"`
		ID         string `json:"id"`
		Action     string `json:"action"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	hosts, _, err := a.deployedHosts(snap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config", err.Error(), nil)
		return
	}
	report, err := a.ssh.ResolveDuplicate(hosts, snap.Keys, req.ConfigHash, req.ID, req.Action)
	if err != nil {
		switch {
		case errors.Is(err, sshutil.ErrConfigChanged):
			writeError(w, http.StatusConflict, "config_changed", err.Error(), nil)
		case errors.Is(err, sshutil.ErrDuplicateNotFound):
			writeError(w, http.StatusNotFound, "duplicate_not_found", err.Error(), nil)
		case errors.Is(err, sshutil.ErrSplitNoPatterns):
			writeError(w, http.StatusBadRequest, "split_no_patterns", err.Error(), nil)
		default:
			writeError(w, http.StatusInternalServerError, "config", err.Error(), nil)
		}
		return
	}
	writeJSON(w, http.StatusOK, report)
}
