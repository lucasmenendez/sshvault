package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sshvault/internal/sshutil"
	"sshvault/internal/vault"
)

type hostRequest struct {
	Revision       int64          `json:"revision"`
	Patterns       []string       `json:"patterns"`
	HostName       string         `json:"hostname"`
	User           string         `json:"user"`
	Port           int            `json:"port"`
	IdentityKeyIDs []string       `json:"identityKeyIds"`
	Options        []vault.Option `json:"options"`
	Deploy         bool           `json:"deploy"`
	Force          bool           `json:"force"`
}

func (a *App) handleHostCreate(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	patterns := splitPatterns(req.Patterns)
	if len(patterns) == 0 {
		writeError(w, http.StatusBadRequest, "validation", "at least one host pattern is required", nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.currentStore().Snapshot(); err != nil {
		locked(w)
		return
	}
	now := time.Now().UTC()
	h := &vault.Host{
		ID:             vault.NewHostID(),
		Patterns:       patterns,
		HostName:       strings.TrimSpace(req.HostName),
		User:           strings.TrimSpace(req.User),
		Port:           req.Port,
		IdentityKeyIDs: req.IdentityKeyIDs,
		Options:        req.Options,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	updated, err := a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		v.Hosts = append(v.Hosts, h)
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
	stored := updated.FindHost(h.ID)
	resp := map[string]any{}
	if req.Deploy {
		if derr := a.deployHostDeps(updated, stored); derr != nil {
			resp["warning"] = "host saved, but could not be deployed: " + derr.Error()
		}
	}
	resp["host"] = a.hostViewFor(updated, stored)
	writeJSON(w, http.StatusCreated, resp)
}

func (a *App) handleHostUpdate(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	patterns := splitPatterns(req.Patterns)
	if len(patterns) == 0 {
		writeError(w, http.StatusBadRequest, "validation", "at least one host pattern is required", nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	old := snap.FindHost(r.PathValue("id"))
	if old == nil {
		notFound(w, "host")
		return
	}
	statuses, cfgErr := a.ssh.HostStatuses(snap.Hosts, snap.Keys)
	oldStatus := statuses[old.ID]
	if cfgErr != nil {
		oldStatus = sshutil.Status{State: sshutil.StateBlocked, Message: cfgErr.Error()}
	}
	if oldStatus.State == sshutil.StateDrift && !req.Force {
		conflict(w, fmt.Errorf("the managed block differs from the vault; confirm overwrite"), oldStatus)
		return
	}
	if oldStatus.State == sshutil.StateBlocked && req.Deploy {
		writeError(w, http.StatusInternalServerError, "config", "cannot write the config while the managed block is malformed: "+oldStatus.Message, nil)
		return
	}
	wasDeployed := oldStatus.State == sshutil.StateDeployed || oldStatus.State == sshutil.StateDrift
	updated, err := a.currentStore().Update(req.Revision, func(v *vault.Vault) error {
		h := v.FindHost(old.ID)
		if h == nil {
			return fmt.Errorf("host disappeared")
		}
		h.Patterns = patterns
		h.HostName = strings.TrimSpace(req.HostName)
		h.User = strings.TrimSpace(req.User)
		h.Port = req.Port
		h.IdentityKeyIDs = req.IdentityKeyIDs
		h.Options = req.Options
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
	stored := updated.FindHost(old.ID)
	resp := map[string]any{}
	if wasDeployed || req.Deploy {
		if derr := a.deployHostDeps(updated, stored); derr != nil {
			resp["warning"] = "host saved, but local config was not updated: " + derr.Error()
		}
	}
	resp["host"] = a.hostViewFor(updated, stored)
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleHostDelete(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	h := snap.FindHost(r.PathValue("id"))
	if h == nil {
		notFound(w, "host")
		return
	}
	statuses, cfgErr := a.ssh.HostStatuses(snap.Hosts, snap.Keys)
	if cfgErr != nil {
		writeError(w, http.StatusInternalServerError, "config", "cannot modify the managed block: "+cfgErr.Error(), nil)
		return
	}
	st := statuses[h.ID]
	if st.State == sshutil.StateDeployed || st.State == sshutil.StateDrift {
		if _, derr := a.ssh.UndeployHost(snap.Hosts, snap.Keys, h.ID); derr != nil {
			internalError(w, derr)
			return
		}
	}
	_, err = a.currentStore().Update(0, func(v *vault.Vault) error {
		idx := -1
		for i, vh := range v.Hosts {
			if vh.ID == h.ID {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("host disappeared")
		}
		v.Hosts = append(v.Hosts[:idx], v.Hosts[idx+1:]...)
		return nil
	})
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (a *App) handleHostDeploy(w http.ResponseWriter, r *http.Request) {
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
	h := snap.FindHost(r.PathValue("id"))
	if h == nil {
		notFound(w, "host")
		return
	}
	if derr := a.deployHostDeps(snap, h); derr != nil {
		writeError(w, http.StatusConflict, "deploy_failed", derr.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": a.hostViewFor(snap, h)})
}

func (a *App) handleHostUndeploy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	h := snap.FindHost(r.PathValue("id"))
	if h == nil {
		notFound(w, "host")
		return
	}
	if _, derr := a.ssh.UndeployHost(snap.Hosts, snap.Keys, h.ID); derr != nil {
		internalError(w, derr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": a.hostViewFor(snap, h)})
}

func (a *App) deployHostDeps(snap *vault.Vault, h *vault.Host) error {
	keysByID := map[string]*vault.Key{}
	for _, k := range snap.Keys {
		keysByID[k.ID] = k
	}
	for _, id := range h.IdentityKeyIDs {
		k := keysByID[id]
		if k == nil {
			continue
		}
		if _, err := a.ssh.DeployKey(k, sshutil.DeployOptions{}); err != nil {
			return fmt.Errorf("identity key %s: %w", k.Alias, err)
		}
	}
	_, err := a.ssh.DeployHost(snap.Hosts, snap.Keys, h.ID)
	return err
}

func (a *App) hostViewFor(snap *vault.Vault, h *vault.Host) hostView {
	statuses, err := a.ssh.HostStatuses(snap.Hosts, snap.Keys)
	st := sshutil.Status{State: sshutil.StateNotDeployed}
	if err == nil {
		if s, ok := statuses[h.ID]; ok {
			st = s
		}
	} else {
		st = sshutil.Status{State: sshutil.StateBlocked, Message: err.Error()}
	}
	keysByID := map[string]*vault.Key{}
	for _, k := range snap.Keys {
		keysByID[k.ID] = k
	}
	return a.makeHostView(h, keysByID, st)
}

func (a *App) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	snap, err := a.currentStore().Snapshot()
	if err != nil {
		locked(w)
		return
	}
	_, deployed, err := a.ssh.ConfigSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config", err.Error(), nil)
		return
	}
	preview, err := a.ssh.ConfigPreview(snap.Hosts, snap.Keys, deployed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":   preview,
		"deployed": deployed,
	})
}
