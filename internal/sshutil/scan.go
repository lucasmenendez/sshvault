package sshutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"sshvault/internal/vault"
)

// ImportItem is a candidate discovered in ~/.ssh. It never contains secret
// content; content is read again during BuildImport.
type ImportItem struct {
	TempID        string         `json:"tempId"`
	Kind          string         `json:"kind"` // key, host, file
	Alias         string         `json:"alias,omitempty"`
	Filename      string         `json:"filename,omitempty"`
	Fingerprint   string         `json:"fingerprint,omitempty"`
	KeyType       string         `json:"keyType,omitempty"`
	HasPrivate    bool           `json:"hasPrivate,omitempty"`
	HasPublic     bool           `json:"hasPublic,omitempty"`
	HasCert       bool           `json:"hasCert,omitempty"`
	PrivateFile   string         `json:"privateFile,omitempty"`
	PublicFile    string         `json:"publicFile,omitempty"`
	CertFile      string         `json:"certFile,omitempty"`
	Patterns      []string       `json:"patterns,omitempty"`
	HostName      string         `json:"hostname,omitempty"`
	User          string         `json:"user,omitempty"`
	Port          int            `json:"port,omitempty"`
	IdentityFiles []string       `json:"identityFiles,omitempty"`
	Options       []vault.Option `json:"options,omitempty"`
	Size          int64          `json:"size,omitempty"`
	Mode          uint32         `json:"mode,omitempty"`
	Encoding      string         `json:"encoding,omitempty"`
	Sensitive     bool           `json:"sensitive,omitempty"`
	Conflict      string         `json:"conflict,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`
}

type Unmanaged struct {
	Name    string `json:"name"`
	Reason  string `json:"reason"`
	Size    int64  `json:"size,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
	Dir     bool   `json:"dir,omitempty"`
	Symlink bool   `json:"symlink,omitempty"`
}

type ScanResult struct {
	Items     []ImportItem `json:"items"`
	Unmanaged []Unmanaged  `json:"unmanaged"`
	Warnings  []string     `json:"warnings"`
}

type ImportPlan struct {
	Keys     []*vault.Key
	Hosts    []*vault.Host
	Files    []*vault.File
	Warnings []string
}

type rawFile struct {
	name    string
	info    os.FileInfo
	content []byte
	text    bool
}

type keyFiles struct {
	private, public, cert *rawFile
}

// Scan discovers importable keys, config hosts and regular files.
func (m *Manager) Scan(current *vault.Vault) (*ScanResult, error) {
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &ScanResult{}, nil
		}
		return nil, err
	}
	result := &ScanResult{Items: []ImportItem{}, Unmanaged: []Unmanaged{}, Warnings: []string{}}

	raw := map[string]*rawFile{}
	var configContent string
	for _, e := range entries {
		name := e.Name()
		if name == "agent" || m.IsInternalFilename(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			result.Unmanaged = append(result.Unmanaged, Unmanaged{Name: name, Reason: "directory (not managed by sshvault)", Dir: true})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			result.Unmanaged = append(result.Unmanaged, Unmanaged{Name: name, Reason: "symlink (not followed)", Symlink: true})
			continue
		}
		if !info.Mode().IsRegular() {
			result.Unmanaged = append(result.Unmanaged, Unmanaged{Name: name, Reason: "not a regular file"})
			continue
		}
		if !ownedByUser(info) {
			result.Unmanaged = append(result.Unmanaged, Unmanaged{Name: name, Reason: "owned by another user", Size: info.Size(), Mode: uint32(info.Mode().Perm())})
			continue
		}
		if info.Size() > vault.MaxFileContent {
			result.Unmanaged = append(result.Unmanaged, Unmanaged{Name: name, Reason: "file is too large", Size: info.Size(), Mode: uint32(info.Mode().Perm())})
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.Dir, name))
		if err != nil {
			result.Unmanaged = append(result.Unmanaged, Unmanaged{Name: name, Reason: err.Error()})
			continue
		}
		if name == "config" {
			configContent = string(b)
			continue
		}
		raw[name] = &rawFile{name: name, info: info, content: b, text: isText(b)}
	}

	sensitive := map[string]bool{
		"authorized_keys": true, "authorized_keys2": true,
		"known_hosts": true, "known_hosts.old": true,
		"rc": true, "environment": true,
	}

	privates := map[string]*rawFile{}
	publics := map[string][]*rawFile{}
	certs := map[string]*rawFile{}
	consumed := map[string]bool{}

	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)

	// Sensitive files, certificates, private keys and public keys first.
	for _, name := range names {
		f := raw[name]
		lower := strings.ToLower(name)
		if sensitive[lower] {
			result.Items = append(result.Items, m.fileItem(f, true))
			consumed[name] = true
			continue
		}
		if idx := strings.Index(lower, "-cert.pub"); idx > 0 {
			if _, err := ParseCertificate(string(f.content)); err == nil {
				base := name[:idx]
				if certs[base] == nil {
					certs[base] = f
				}
				consumed[name] = true
				continue
			}
			// A *-cert.pub file that is not actually a certificate is a normal file.
			result.Items = append(result.Items, m.fileItem(f, false))
			consumed[name] = true
			continue
		}
		if IsPrivateKey(string(f.content)) {
			privates[name] = f
			consumed[name] = true
			continue
		}
		if IsPublicKey(string(f.content)) {
			base := name
			if idx := strings.Index(lower, ".pub"); idx > 0 {
				base = name[:idx]
			}
			publics[base] = append(publics[base], f)
			consumed[name] = true
		}
	}

	// Keys are the union of private bases, public bases and certificate bases.
	bases := map[string]bool{}
	for base := range privates {
		bases[base] = true
	}
	for base := range publics {
		bases[base] = true
	}
	for base := range certs {
		bases[base] = true
	}
	keyBases := make([]string, 0, len(bases))
	for base := range bases {
		keyBases = append(keyBases, base)
	}
	sort.Strings(keyBases)
	for _, base := range keyBases {
		private := privates[base]
		public, extras := pickPublic(base, publics[base])
		cert := certs[base]
		item := m.keyItem(base, private, public, cert)
		item.PrivateFile = fileName(private)
		item.PublicFile = fileName(public)
		item.CertFile = fileName(cert)
		if len(extras) > 0 {
			item.Warnings = append(item.Warnings, "multiple public files for "+base+"; using "+fileName(public))
		}
		result.Items = append(result.Items, item)
	}

	// Anything left is a regular file.
	for _, name := range names {
		if consumed[name] {
			continue
		}
		result.Items = append(result.Items, m.fileItem(raw[name], false))
	}

	if configContent != "" {
		hosts, warnings := parseConfigHosts(configContent)
		result.Warnings = append(result.Warnings, warnings...)
		result.Items = append(result.Items, hosts...)
	}

	markConflicts(result, current)

	sort.SliceStable(result.Items, func(i, j int) bool {
		order := map[string]int{"key": 0, "host": 1, "file": 2}
		if result.Items[i].Kind != result.Items[j].Kind {
			return order[result.Items[i].Kind] < order[result.Items[j].Kind]
		}
		if result.Items[i].Kind == "host" {
			return strings.Join(result.Items[i].Patterns, " ") < strings.Join(result.Items[j].Patterns, " ")
		}
		return strings.ToLower(result.Items[i].Filename) < strings.ToLower(result.Items[j].Filename)
	})
	return result, nil
}

func markConflicts(result *ScanResult, current *vault.Vault) {
	if current == nil {
		return
	}
	for i := range result.Items {
		it := &result.Items[i]
		switch it.Kind {
		case "key":
			if it.Fingerprint != "" {
				for _, k := range current.Keys {
					if k.Fingerprint == it.Fingerprint {
						it.Conflict = "already in vault"
						break
					}
				}
			}
			if it.Conflict == "" && nameTaken(current, it.Filename) {
				it.Conflict = "filename already used in vault"
			}
		case "file":
			if nameTaken(current, it.Filename) {
				it.Conflict = "filename already used in vault"
			}
		case "host":
			if hostPatternsTaken(current, it.Patterns) {
				it.Conflict = "host pattern already in vault"
			}
		}
	}
}

func nameTaken(v *vault.Vault, name string) bool {
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

func hostPatternsTaken(v *vault.Vault, patterns []string) bool {
	set := map[string]bool{}
	for _, h := range v.Hosts {
		for _, p := range h.Patterns {
			set[strings.ToLower(p)] = true
		}
	}
	for _, p := range patterns {
		if set[strings.ToLower(p)] {
			return true
		}
	}
	return false
}

func (m *Manager) fileItem(f *rawFile, sensitive bool) ImportItem {
	encoding := vault.EncodingUTF8
	if !f.text {
		encoding = vault.EncodingBase64
	}
	mode := uint32(f.info.Mode().Perm())
	warnings := []string{}
	if mode != 0o600 && mode != 0o640 && mode != 0o644 {
		warnings = append(warnings, fmt.Sprintf("unsupported mode %04o; will be imported as 0600", mode))
		mode = 0o600
	}
	return ImportItem{
		TempID:    "file:" + f.name,
		Kind:      "file",
		Filename:  f.name,
		Size:      f.info.Size(),
		Mode:      mode,
		Encoding:  encoding,
		Sensitive: sensitive,
		Warnings:  warnings,
	}
}

func (m *Manager) keyItem(base string, private, public, cert *rawFile) ImportItem {
	item := ImportItem{
		TempID:      "key:" + base,
		Kind:        "key",
		Filename:    base,
		Alias:       keyAlias(base),
		HasPrivate:  private != nil,
		HasPublic:   public != nil,
		HasCert:     cert != nil,
		PrivateFile: fileName(private),
		PublicFile:  fileName(public),
		CertFile:    fileName(cert),
		Warnings:    []string{},
	}
	k := &vault.Key{Filename: base, Alias: item.Alias}
	if private != nil {
		k.PrivateKey = string(private.content)
	}
	if public != nil {
		k.PublicKey = string(public.content)
	}
	if cert != nil {
		k.Certificate = string(cert.content)
	}
	k.Kind = Kind(k.PublicKey, k.PrivateKey, k.Certificate)
	if info, err := Inspect(k); err == nil {
		item.Fingerprint = info.Fingerprint
		item.KeyType = info.Type
		if info.Comment != "" {
			item.Warnings = append(item.Warnings, "key comment: "+info.Comment)
		}
	} else {
		item.Warnings = append(item.Warnings, err.Error())
	}
	if private != nil && public == nil {
		if _, err := publicFromPrivateBytes(private.content); err != nil {
			item.Warnings = append(item.Warnings, "private key is encrypted or unreadable; add a public key if needed")
		}
	}
	if cert != nil {
		if _, err := ParseCertificate(string(cert.content)); err != nil {
			item.Warnings = append(item.Warnings, "certificate could not be parsed: "+err.Error())
		}
	}
	return item
}

func keyAlias(base string) string {
	a := base
	a = strings.TrimPrefix(a, "id_")
	a = strings.TrimSuffix(a, ".pub")
	a = strings.TrimSuffix(a, "-cert")
	if a == "" {
		a = base
	}
	return a
}

func publicFromPrivateBytes(b []byte) (string, error) {
	return PublicFromPrivate(string(b), "", "")
}

func ownedByUser(info os.FileInfo) bool {
	return owned(info)
}

func owned(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return int(st.Uid) == os.Getuid()
}

func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

func parseConfigHosts(content string) ([]ImportItem, []string) {
	var items []ImportItem
	var warnings []string
	var cur *ImportItem
	flush := func() {
		if cur == nil {
			return
		}
		if len(cur.Patterns) == 0 {
			cur = nil
			return
		}
		cur.TempID = "host:" + strings.Join(cur.Patterns, " ")
		cur.Kind = "host"
		items = append(items, *cur)
		cur = nil
	}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "host":
			flush()
			if len(fields) < 2 {
				warnings = append(warnings, "config: Host line without patterns")
				continue
			}
			var patterns []string
			for _, p := range fields[1:] {
				p = strings.Trim(p, `"'`)
				if p == "" || strings.ContainsAny(p, "#\r\n\x00") {
					warnings = append(warnings, "config: skipped invalid host pattern "+p)
					continue
				}
				patterns = append(patterns, p)
			}
			cur = &ImportItem{Patterns: patterns, Warnings: []string{}}
			for _, p := range patterns {
				if p == "*" {
					cur.Warnings = append(cur.Warnings, "global Host * entry; it may override other hosts")
				}
			}
			continue
		case "match", "include":
			flush()
			warnings = append(warnings, "config: "+fields[0]+" blocks are not imported")
			cur = nil
			continue
		}
		if cur == nil {
			continue
		}
		name := fields[0]
		value := strings.Join(fields[1:], " ")
		if len(fields) == 1 && strings.Contains(name, "=") {
			parts := strings.SplitN(name, "=", 2)
			name, value = parts[0], parts[1]
		}
		switch strings.ToLower(name) {
		case "hostname":
			if len(fields) > 1 {
				cur.HostName = fields[1]
			}
		case "user":
			if len(fields) > 1 {
				cur.User = fields[1]
			}
		case "port":
			if len(fields) > 1 {
				if p, err := strconv.Atoi(fields[1]); err == nil {
					cur.Port = p
				} else {
					cur.Warnings = append(cur.Warnings, "invalid port: "+fields[1])
				}
			}
		case "identityfile":
			if len(fields) > 1 {
				v := strings.Trim(fields[1], `"'`)
				if v != "" {
					cur.IdentityFiles = append(cur.IdentityFiles, filepath.Base(v))
				}
			}
		default:
			if name != "" {
				cur.Options = append(cur.Options, vault.Option{Name: name, Value: value})
			}
		}
	}
	flush()
	return items, warnings
}

// BuildImport reads the selected items again and turns them into vault entries.
func (m *Manager) BuildImport(current *vault.Vault, selected map[string]bool) (*ImportPlan, error) {
	scan, err := m.Scan(current)
	if err != nil {
		return nil, err
	}
	plan := &ImportPlan{Warnings: []string{}}
	knownNames := map[string]bool{}
	claim := func(name string) bool {
		key := strings.ToLower(name)
		if knownNames[key] {
			return false
		}
		knownNames[key] = true
		return true
	}
	for _, k := range current.Keys {
		knownNames[strings.ToLower(k.Filename)] = true
		knownNames[strings.ToLower(k.Filename+".pub")] = true
		knownNames[strings.ToLower(k.Filename+"-cert.pub")] = true
	}
	for _, f := range current.Files {
		knownNames[strings.ToLower(f.Filename)] = true
	}
	usedAliases := map[string]bool{}
	for _, k := range current.Keys {
		usedAliases[strings.ToLower(k.Alias)] = true
	}
	keyByFilename := map[string]string{}
	for _, k := range current.Keys {
		keyByFilename[strings.ToLower(k.Filename)] = k.ID
	}
	usedPatterns := map[string]bool{}
	for _, h := range current.Hosts {
		for _, p := range h.Patterns {
			usedPatterns[strings.ToLower(p)] = true
		}
	}

	raw := map[string]*rawFile{}
	entries, _ := os.ReadDir(m.Dir)
	for _, e := range entries {
		name := e.Name()
		if name == "config" || name == "agent" || m.IsInternalFilename(name) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > vault.MaxFileContent {
			continue
		}
		if !owned(info) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.Dir, name))
		if err != nil {
			continue
		}
		raw[name] = &rawFile{name: name, info: info, content: b, text: isText(b)}
	}

	for _, item := range scan.Items {
		if item.Kind != "key" || !selected[item.TempID] {
			continue
		}
		if item.Conflict == "already in vault" {
			if item.Fingerprint != "" {
				for _, k := range current.Keys {
					if k.Fingerprint == item.Fingerprint {
						keyByFilename[strings.ToLower(item.Filename)] = k.ID
					}
				}
			}
			continue
		}
		if item.Conflict != "" {
			plan.Warnings = append(plan.Warnings, "skipped key "+item.Filename+": "+item.Conflict)
			continue
		}
		if err := vault.CheckFilename(item.Filename, true); err != nil {
			plan.Warnings = append(plan.Warnings, "skipped key "+item.Filename+": "+err.Error())
			continue
		}
		if !claim(item.Filename) {
			plan.Warnings = append(plan.Warnings, "skipped key "+item.Filename+": filename already used")
			continue
		}
		parts := keyPartsForItem(raw, item)
		k := &vault.Key{
			ID:        vault.NewKeyID(),
			Alias:     uniqueAlias(item.Alias, usedAliases),
			Filename:  item.Filename,
			Tags:      []string{"imported"},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		if parts.private != nil {
			k.PrivateKey = string(parts.private.content)
		}
		if parts.public != nil {
			k.PublicKey = string(parts.public.content)
		}
		if parts.cert != nil {
			k.Certificate = string(parts.cert.content)
		}
		k.Kind = Kind(k.PublicKey, k.PrivateKey, k.Certificate)
		if info, err := Inspect(k); err == nil {
			k.Fingerprint = info.Fingerprint
			if k.Comment == "" {
				k.Comment = info.Comment
			}
		}
		k.PublicKey = normalizeImportedText(k.PublicKey)
		k.PrivateKey = normalizeImportedText(k.PrivateKey)
		k.Certificate = normalizeImportedText(k.Certificate)
		plan.Keys = append(plan.Keys, k)
		keyByFilename[strings.ToLower(k.Filename)] = k.ID
		claim(k.Filename + ".pub")
		claim(k.Filename + "-cert.pub")
	}

	for _, item := range scan.Items {
		if item.Kind != "file" || !selected[item.TempID] {
			continue
		}
		if item.Conflict != "" {
			plan.Warnings = append(plan.Warnings, "skipped file "+item.Filename+": "+item.Conflict)
			continue
		}
		if err := vault.CheckFilename(item.Filename, false); err != nil {
			plan.Warnings = append(plan.Warnings, "skipped file "+item.Filename+": "+err.Error())
			continue
		}
		f := raw[item.Filename]
		if f == nil {
			plan.Warnings = append(plan.Warnings, "skipped file "+item.Filename+": disappeared")
			continue
		}
		if !claim(item.Filename) {
			plan.Warnings = append(plan.Warnings, "skipped file "+item.Filename+": filename already used")
			continue
		}
		file := &vault.File{
			ID:        vault.NewFileID(),
			Filename:  item.Filename,
			Mode:      item.Mode,
			Tags:      []string{"imported"},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		file.SetContentBytes(f.content)
		plan.Files = append(plan.Files, file)
	}

	for _, item := range scan.Items {
		if item.Kind != "host" || !selected[item.TempID] {
			continue
		}
		if item.Conflict != "" {
			plan.Warnings = append(plan.Warnings, "skipped host "+strings.Join(item.Patterns, " ")+": "+item.Conflict)
			continue
		}
		duplicate := false
		for _, p := range item.Patterns {
			if usedPatterns[strings.ToLower(p)] {
				duplicate = true
				break
			}
		}
		if duplicate {
			plan.Warnings = append(plan.Warnings, "skipped host "+strings.Join(item.Patterns, " ")+": pattern already used")
			continue
		}
		h := &vault.Host{
			ID:        vault.NewHostID(),
			Patterns:  append([]string(nil), item.Patterns...),
			HostName:  item.HostName,
			User:      item.User,
			Port:      item.Port,
			Options:   append([]vault.Option(nil), item.Options...),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		for _, p := range item.Patterns {
			usedPatterns[strings.ToLower(p)] = true
		}
		for _, file := range item.IdentityFiles {
			if id := keyByFilename[strings.ToLower(file)]; id != "" {
				h.IdentityKeyIDs = append(h.IdentityKeyIDs, id)
			} else {
				plan.Warnings = append(plan.Warnings, "host "+strings.Join(item.Patterns, " ")+": IdentityFile "+file+" was not imported")
			}
		}
		plan.Hosts = append(plan.Hosts, h)
	}
	return plan, nil
}

func keyPartsFor(raw map[string]*rawFile, base string) keyFiles {
	return keyFiles{
		private: raw[base],
		public:  raw[base+".pub"],
		cert:    raw[base+"-cert.pub"],
	}
}

func keyPartsForItem(raw map[string]*rawFile, item ImportItem) keyFiles {
	get := func(name string) *rawFile {
		if name == "" {
			return nil
		}
		return raw[name]
	}
	parts := keyFiles{
		private: get(item.PrivateFile),
		public:  get(item.PublicFile),
		cert:    get(item.CertFile),
	}
	if parts.private == nil && parts.public == nil && parts.cert == nil {
		return keyPartsFor(raw, item.Filename)
	}
	return parts
}

func pickPublic(base string, list []*rawFile) (*rawFile, []string) {
	if len(list) == 0 {
		return nil, nil
	}
	sort.SliceStable(list, func(i, j int) bool {
		exactI := strings.EqualFold(list[i].name, base+".pub")
		exactJ := strings.EqualFold(list[j].name, base+".pub")
		if exactI != exactJ {
			return exactI
		}
		return strings.ToLower(list[i].name) < strings.ToLower(list[j].name)
	})
	extras := make([]string, 0, len(list)-1)
	for _, f := range list[1:] {
		extras = append(extras, f.name)
	}
	return list[0], extras
}

func fileName(f *rawFile) string {
	if f == nil {
		return ""
	}
	return f.name
}

func uniqueAlias(alias string, used map[string]bool) string {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "key"
	}
	candidate := alias
	for i := 2; used[strings.ToLower(candidate)]; i++ {
		candidate = fmt.Sprintf("%s-%d", alias, i)
	}
	used[strings.ToLower(candidate)] = true
	return candidate
}

func normalizeImportedText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return s + "\n"
}
