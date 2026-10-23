package preferences

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Config is the small, non-secret user configuration kept outside the vault.
// It only contains the opt-in startup behavior and a vault path.
type Config struct {
	RememberVault bool   `json:"rememberVault"`
	LastVaultPath string `json:"lastVaultPath,omitempty"`
}

// Manager serializes reads and writes of the preferences file.
type Manager struct {
	mu   sync.Mutex
	path string
	cfg  Config
}

// DefaultPath returns the per-user preferences path.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sshvault", "config.json"), nil
}

// Open loads preferences from path. A missing file is not an error. If the
// file is malformed or unreadable, the returned Manager still points at path
// so the setting can be repaired by a later write.
func Open(path string) (*Manager, error) {
	m := &Manager{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m, nil
		}
		return m, fmt.Errorf("read preferences: %w", err)
	}
	if len(data) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m.cfg); err != nil {
		return m, fmt.Errorf("parse preferences: %w", err)
	}
	return m, nil
}

// New returns an in-memory preferences manager without reading the file.
func New(path string) *Manager { return &Manager{path: path} }

// Config returns a copy of the current preferences.
func (m *Manager) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// SetRemember enables or disables remembering the current vault. Enabling
// stores currentPath; disabling clears the stored path.
func (m *Manager) SetRemember(enabled bool, currentPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	next := m.cfg
	next.RememberVault = enabled
	if enabled {
		next.LastVaultPath = currentPath
	} else {
		next.LastVaultPath = ""
	}
	if err := save(m.path, next); err != nil {
		return err
	}
	m.cfg = next
	return nil
}

// Remember records a successfully unlocked or created vault path when the
// opt-in setting is enabled. It is a no-op otherwise.
func (m *Manager) Remember(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.RememberVault || path == "" || m.cfg.LastVaultPath == path {
		return nil
	}
	next := m.cfg
	next.LastVaultPath = path
	if err := save(m.path, next); err != nil {
		return err
	}
	m.cfg = next
	return nil
}

func save(path string, cfg Config) error {
	if path == "" {
		return errors.New("preferences path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create preferences directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".sshvault-config-*")
	if err != nil {
		return fmt.Errorf("create preferences file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}
