package sshutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"sshvault/internal/vault"
)

const (
	StateNotDeployed = "not_deployed"
	StateDeployed    = "deployed"
	StatePartial     = "partial"
	StateDrift       = "drift"
	StateMode        = "mode"
	StateBlocked     = "blocked"
)

// ConflictError means a local file exists but does not match the vault and the
// caller did not explicitly force an overwrite.
type ConflictError struct {
	Path   string
	Reason string
}

func (e *ConflictError) Error() string {
	if e.Reason == "" {
		return "local file conflicts with vault: " + e.Path
	}
	return "local file conflicts with vault: " + e.Path + " (" + e.Reason + ")"
}

type FileState struct {
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	Match     bool   `json:"match"`
	ModeOK    bool   `json:"modeOk"`
	IsSymlink bool   `json:"isSymlink"`
	Error     string `json:"error,omitempty"`
}

type Status struct {
	State   string      `json:"state"`
	Files   []FileState `json:"files"`
	Message string      `json:"message,omitempty"`
}

type ExpectedFile struct {
	Path    string
	Content []byte
	Mode    os.FileMode
	Text    bool
}

type DeployOptions struct {
	Force bool
}

// Manager projects vault entries into a real ~/.ssh directory.
type Manager struct {
	Dir         string
	Home        string
	vaultPath   string
	vaultPathMu sync.RWMutex
	mu          sync.Mutex
	configMu    sync.Mutex
}

func NewManager(dir string) (*Manager, error) {
	if dir == "" || dir == "~/.ssh" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, ".ssh")
	} else if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, dir[2:])
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	return &Manager{Dir: abs, Home: home}, nil
}

func (m *Manager) ConfigPath() string { return filepath.Join(m.Dir, "config") }

// SetVaultPath tells the manager where the encrypted vault lives so its
// sidecars are never offered as importable SSH files.
func (m *Manager) SetVaultPath(path string) {
	m.vaultPathMu.Lock()
	m.vaultPath = path
	m.vaultPathMu.Unlock()
}

// IsInternalFilename reports whether name belongs to sshvault itself rather
// than to the user's SSH configuration.
func (m *Manager) IsInternalFilename(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".sshvault") {
		return true
	}
	if strings.Contains(lower, ".vault") {
		return true
	}
	m.vaultPathMu.RLock()
	vaultPath := m.vaultPath
	m.vaultPathMu.RUnlock()
	if vaultPath == "" {
		return false
	}
	if samePath(filepath.Dir(vaultPath), m.Dir) {
		base := strings.ToLower(filepath.Base(vaultPath))
		if lower == base || lower == base+".lock" || strings.HasPrefix(lower, base+".bak.") {
			return true
		}
	}
	if samePath(filepath.Join(m.Dir, name), vaultPath) {
		return true
	}
	if samePath(filepath.Join(m.Dir, name), vaultPath+".lock") {
		return true
	}
	return false
}

func samePath(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		ra = a
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		rb = b
	}
	aa, err := filepath.Abs(ra)
	if err != nil {
		return false
	}
	bb, err := filepath.Abs(rb)
	if err != nil {
		return false
	}
	return aa == bb
}

func (m *Manager) EnsureDir() error {
	info, err := os.Stat(m.Dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", m.Dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(m.Dir, 0o700)
}

func (m *Manager) DisplayPath(filename string) string {
	if m.Home != "" && m.Dir == filepath.Join(m.Home, ".ssh") {
		return "~/.ssh/" + filename
	}
	return filepath.Join(m.Dir, filename)
}

func (m *Manager) Path(filename string) string {
	return filepath.Join(m.Dir, filename)
}

func (m *Manager) keyFiles(k *vault.Key) []ExpectedFile {
	base := m.Path(k.Filename)
	var out []ExpectedFile
	if k.PrivateKey != "" {
		out = append(out, ExpectedFile{Path: base, Content: []byte(k.PrivateKey), Mode: 0o600, Text: true})
	}
	if k.PublicKey != "" {
		out = append(out, ExpectedFile{Path: base + ".pub", Content: []byte(k.PublicKey), Mode: 0o644, Text: true})
	}
	if k.Certificate != "" {
		out = append(out, ExpectedFile{Path: base + "-cert.pub", Content: []byte(k.Certificate), Mode: 0o644, Text: true})
	}
	return out
}

func (m *Manager) KeyStatus(k *vault.Key) Status {
	return m.status(m.keyFiles(k))
}

func (m *Manager) FileStatus(f *vault.File) Status {
	b, err := f.ContentBytes()
	if err != nil {
		return Status{State: StateBlocked, Message: err.Error()}
	}
	return m.status([]ExpectedFile{{Path: m.Path(f.Filename), Content: b, Mode: os.FileMode(f.Mode), Text: false}})
}

func (m *Manager) status(files []ExpectedFile) Status {
	if len(files) == 0 {
		return Status{State: StateBlocked, Message: "entry has no files to deploy"}
	}
	out := Status{State: StateNotDeployed, Files: make([]FileState, 0, len(files))}
	existsCount, matchCount, modeBad := 0, 0, false
	blocked := false
	drift := false
	for _, want := range files {
		fs := FileState{Path: want.Path}
		info, err := os.Lstat(want.Path)
		if err != nil {
			if !os.IsNotExist(err) {
				fs.Error = err.Error()
				blocked = true
			}
			out.Files = append(out.Files, fs)
			continue
		}
		fs.Exists = true
		existsCount++
		if info.Mode()&os.ModeSymlink != 0 {
			fs.IsSymlink = true
			fs.Error = "is a symlink"
			blocked = true
			out.Files = append(out.Files, fs)
			continue
		}
		if !info.Mode().IsRegular() {
			fs.Error = "is not a regular file"
			blocked = true
			out.Files = append(out.Files, fs)
			continue
		}
		actual, err := os.ReadFile(want.Path)
		if err != nil {
			fs.Error = err.Error()
			blocked = true
			out.Files = append(out.Files, fs)
			continue
		}
		fs.Match = contentEqual(want.Content, actual, want.Text)
		if fs.Match {
			matchCount++
		} else {
			drift = true
		}
		fs.ModeOK = info.Mode().Perm() == want.Mode
		if !fs.ModeOK {
			modeBad = true
		}
		out.Files = append(out.Files, fs)
	}
	switch {
	case blocked:
		out.State = StateBlocked
		out.Message = "one or more paths are blocked"
	case drift:
		out.State = StateDrift
		out.Message = "local content differs from the vault"
	case modeBad:
		out.State = StateMode
		out.Message = "local permissions differ from the vault"
	case existsCount == 0:
		out.State = StateNotDeployed
	case matchCount == len(files):
		out.State = StateDeployed
	default:
		out.State = StatePartial
		out.Message = "some files are missing locally"
	}
	return out
}

func (m *Manager) DeployKey(k *vault.Key, opts DeployOptions) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.EnsureDir(); err != nil {
		return Status{}, err
	}
	for _, want := range m.keyFiles(k) {
		if err := m.writeExpected(want, opts.Force, false); err != nil {
			return m.KeyStatus(k), err
		}
	}
	return m.KeyStatus(k), nil
}

func (m *Manager) DeployFile(f *vault.File, opts DeployOptions) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.EnsureDir(); err != nil {
		return Status{}, err
	}
	b, err := f.ContentBytes()
	if err != nil {
		return Status{}, err
	}
	want := ExpectedFile{Path: m.Path(f.Filename), Content: b, Mode: os.FileMode(f.Mode), Text: false}
	if err := m.writeExpected(want, opts.Force, true); err != nil {
		return m.FileStatus(f), err
	}
	return m.FileStatus(f), nil
}

func (m *Manager) writeExpected(want ExpectedFile, force, backup bool) error {
	info, err := os.Lstat(want.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return writeAtomic(want.Path, want.Content, want.Mode)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return &ConflictError{Path: want.Path, Reason: "is a symlink"}
	}
	if !info.Mode().IsRegular() {
		return &ConflictError{Path: want.Path, Reason: "is not a regular file"}
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return &ConflictError{Path: want.Path, Reason: "is owned by another user"}
	}
	actual, err := os.ReadFile(want.Path)
	if err != nil {
		return err
	}
	match := contentEqual(want.Content, actual, want.Text)
	if !match && !force {
		return &ConflictError{Path: want.Path, Reason: "content differs"}
	}
	if match && info.Mode().Perm() == want.Mode {
		return nil
	}
	if !match && backup {
		if err := m.backupFile(want.Path); err != nil {
			return err
		}
	}
	if match {
		return os.Chmod(want.Path, want.Mode)
	}
	return writeAtomic(want.Path, want.Content, want.Mode)
}

func (m *Manager) UndeployKey(k *vault.Key, force bool) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	base := m.Path(k.Filename)
	for _, path := range []string{base, base + ".pub", base + "-cert.pub"} {
		if err := removeManaged(path, force); err != nil {
			return m.KeyStatus(k), err
		}
	}
	return m.KeyStatus(k), nil
}

func (m *Manager) UndeployFile(f *vault.File, force bool) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := removeManaged(m.Path(f.Filename), force); err != nil {
		return m.FileStatus(f), err
	}
	return m.FileStatus(f), nil
}

func removeManaged(path string, force bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return &ConflictError{Path: path, Reason: "is a symlink"}
	}
	if !info.Mode().IsRegular() {
		return &ConflictError{Path: path, Reason: "is not a regular file"}
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return &ConflictError{Path: path, Reason: "is owned by another user"}
	}
	if !force {
		return &ConflictError{Path: path, Reason: "refusing to delete without confirmation"}
	}
	return os.Remove(path)
}

func (m *Manager) backupFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dir := filepath.Join(m.Dir, ".sshvault-backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000")
	name := filepath.Base(path) + "." + stamp + ".bak"
	if err := writeAtomic(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	pruneDir(dir, 20)
	return nil
}

func pruneDir(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= keep {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, old := range names[:max(0, len(names)-keep)] {
		_ = os.Remove(filepath.Join(dir, old))
	}
}

func contentEqual(expected, actual []byte, text bool) bool {
	if !text {
		return bytes.Equal(expected, actual)
	}
	return normalizeText(string(expected)) == normalizeText(string(actual))
}

func normalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(s) + "\n"
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sshvault-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(mode); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// LocalFile is an entry discovered while scanning ~/.ssh.
type LocalFile struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Mode    uint32    `json:"mode"`
	ModTime time.Time `json:"modTime"`
	Symlink bool      `json:"symlink"`
	Dir     bool      `json:"dir"`
	Owned   bool      `json:"owned"`
	Content []byte    `json:"-"`
}

// ScanLocal lists direct children of the SSH directory without following links.
func (m *Manager) ScanLocal() ([]LocalFile, error) {
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []LocalFile
	for _, e := range entries {
		name := e.Name()
		if name == "config" || name == "config.d" || name == "agent" || m.IsInternalFilename(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		lf := LocalFile{
			Name:    name,
			Size:    info.Size(),
			Mode:    uint32(info.Mode().Perm()),
			ModTime: info.ModTime(),
			Dir:     info.IsDir(),
			Symlink: info.Mode()&os.ModeSymlink != 0,
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			lf.Owned = int(st.Uid) == os.Getuid()
		} else {
			lf.Owned = true
		}
		if !lf.Dir && !lf.Symlink && info.Mode().IsRegular() && info.Size() <= vault.MaxFileContent {
			if b, err := os.ReadFile(filepath.Join(m.Dir, name)); err == nil {
				lf.Content = b
			}
		}
		out = append(out, lf)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func IsConflict(err error) bool {
	var c *ConflictError
	return errors.As(err, &c)
}
