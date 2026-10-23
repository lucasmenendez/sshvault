package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	VaultVersion = 1

	KeyKindKeypair     = "keypair"
	KeyKindCertificate = "certificate"
	KeyKindPublic      = "public"

	EncodingUTF8   = "utf8"
	EncodingBase64 = "base64"

	MaxKeyField     = 1 << 20 // 1 MiB
	MaxFileContent  = 4 << 20 // 4 MiB
	MaxVaultSize    = 32 << 20
	MaxTags         = 20
	MaxTagLength    = 32
	MaxDescription  = 512
	MaxHostOptions  = 64
	MaxOptionValue  = 2048
	MaxPatterns     = 16
	MaxIdentityKeys = 16
)

// Vault is the decrypted document stored inside ssh.vault.
type Vault struct {
	Version   int       `json:"version"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Keys      []*Key    `json:"keys"`
	Hosts     []*Host   `json:"hosts"`
	Files     []*File   `json:"files"`
}

// Key is an SSH key, public key or certificate managed by the vault.
type Key struct {
	ID          string    `json:"id"`
	Alias       string    `json:"alias"`
	Filename    string    `json:"filename"`
	Tags        []string  `json:"tags"`
	Kind        string    `json:"kind"`
	PublicKey   string    `json:"publicKey"`
	PrivateKey  string    `json:"privateKey"`
	Certificate string    `json:"certificate"`
	Comment     string    `json:"comment"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Option is an ordered ssh_config directive.
type Option struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Host is one Host block in ~/.ssh/config.
type Host struct {
	ID             string    `json:"id"`
	Patterns       []string  `json:"patterns"`
	HostName       string    `json:"hostname"`
	User           string    `json:"user"`
	Port           int       `json:"port"`
	IdentityKeyIDs []string  `json:"identityKeyIds"`
	Options        []Option  `json:"options"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// File is a generic file inside ~/.ssh (known_hosts, authorized_keys, ...).
type File struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	Encoding    string    `json:"encoding"`
	Content     string    `json:"content"`
	Mode        uint32    `json:"mode"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func NewVault() *Vault {
	now := time.Now().UTC()
	return &Vault{
		Version:   VaultVersion,
		Revision:  1,
		CreatedAt: now,
		UpdatedAt: now,
		Keys:      []*Key{},
		Hosts:     []*Host{},
		Files:     []*File{},
	}
}

// Clone returns a deep copy through JSON, which is cheap for vault-sized data.
func (v *Vault) Clone() (*Vault, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out Vault
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func NewID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("vault: crypto/rand failed: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func NewKeyID() string  { return NewID("k") }
func NewHostID() string { return NewID("h") }
func NewFileID() string { return NewID("f") }

func (v *Vault) FindKey(id string) *Key {
	for _, k := range v.Keys {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (v *Vault) FindHost(id string) *Host {
	for _, h := range v.Hosts {
		if h.ID == id {
			return h
		}
	}
	return nil
}

func (v *Vault) FindFile(id string) *File {
	for _, f := range v.Files {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func (v *Vault) KeyByFilename(name string) *Key {
	for _, k := range v.Keys {
		if strings.EqualFold(k.Filename, name) {
			return k
		}
	}
	return nil
}

func (v *Vault) FileByFilename(name string) *File {
	for _, f := range v.Files {
		if strings.EqualFold(f.Filename, name) {
			return f
		}
	}
	return nil
}

// AllTags returns the sorted, deduplicated set of tags in the vault.
func (v *Vault) AllTags() []string {
	seen := map[string]string{}
	add := func(tags []string) {
		for _, t := range tags {
			key := strings.ToLower(t)
			if _, ok := seen[key]; !ok {
				seen[key] = t
			}
		}
	}
	for _, k := range v.Keys {
		add(k.Tags)
	}
	for _, f := range v.Files {
		add(f.Tags)
	}
	out := make([]string, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sortStringsFold(out)
	return out
}

func sortStringsFold(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && strings.ToLower(s[j]) < strings.ToLower(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Normalize trims and deduplicates user-provided values in place.
func (v *Vault) Normalize() {
	for _, k := range v.Keys {
		k.Alias = strings.TrimSpace(k.Alias)
		k.Filename = strings.TrimSpace(k.Filename)
		k.Comment = strings.TrimSpace(k.Comment)
		k.Tags = NormalizeTags(k.Tags)
		k.PublicKey = normalizeKeyText(k.PublicKey)
		k.PrivateKey = normalizeKeyText(k.PrivateKey)
		k.Certificate = normalizeKeyText(k.Certificate)
	}
	for _, h := range v.Hosts {
		h.Patterns = normalizePatterns(h.Patterns)
		h.HostName = strings.TrimSpace(h.HostName)
		h.User = strings.TrimSpace(h.User)
		h.IdentityKeyIDs = dedupeStrings(h.IdentityKeyIDs)
		for i := range h.Options {
			h.Options[i].Name = strings.TrimSpace(h.Options[i].Name)
			h.Options[i].Value = strings.TrimSpace(h.Options[i].Value)
		}
	}
	for _, f := range v.Files {
		f.Filename = strings.TrimSpace(f.Filename)
		f.Description = strings.TrimSpace(f.Description)
		f.Tags = NormalizeTags(f.Tags)
		if f.Encoding == "" {
			f.Encoding = EncodingUTF8
		}
		if f.Mode == 0 {
			f.Mode = 0o600
		}
	}
}

func normalizeKeyText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return s + "\n"
}

func NormalizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		key := strings.ToLower(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func normalizePatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

var (
	filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	optionPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
)

var reservedForAll = map[string]bool{
	"config":            true,
	"config.d":          true,
	"agent":             true,
	".sshvault-backups": true,
}

var reservedForKey = map[string]bool{
	"known_hosts":      true,
	"known_hosts.old":  true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"rc":               true,
	"environment":      true,
}

var forbiddenOptionNames = map[string]bool{
	"host":         true,
	"match":        true,
	"include":      true,
	"hostname":     true,
	"user":         true,
	"port":         true,
	"identityfile": true,
}

// Validate checks structural invariants. Call Normalize first.
func (v *Vault) Validate() error {
	if v.Version != VaultVersion {
		return fmt.Errorf("unsupported vault schema version %d", v.Version)
	}
	if v.Revision < 1 {
		return fmt.Errorf("invalid vault revision")
	}

	ids := map[string]bool{}
	for _, k := range v.Keys {
		if k == nil {
			return fmt.Errorf("nil key entry")
		}
		if k.ID == "" || ids[k.ID] {
			return fmt.Errorf("duplicate or empty key id %q", k.ID)
		}
		ids[k.ID] = true
		if err := validateKey(k); err != nil {
			return err
		}
	}
	for _, h := range v.Hosts {
		if h == nil {
			return fmt.Errorf("nil host entry")
		}
		if h.ID == "" || ids[h.ID] {
			return fmt.Errorf("duplicate or empty host id %q", h.ID)
		}
		ids[h.ID] = true
		if err := validateHost(h); err != nil {
			return err
		}
	}
	for _, f := range v.Files {
		if f == nil {
			return fmt.Errorf("nil file entry")
		}
		if f.ID == "" || ids[f.ID] {
			return fmt.Errorf("duplicate or empty file id %q", f.ID)
		}
		ids[f.ID] = true
		if err := validateFile(f); err != nil {
			return err
		}
	}

	if err := validateUniqueNames(v); err != nil {
		return err
	}
	if err := validateUniqueHostPatterns(v); err != nil {
		return err
	}
	for _, h := range v.Hosts {
		for _, id := range h.IdentityKeyIDs {
			if v.FindKey(id) == nil {
				return fmt.Errorf("host %q references unknown key %q", h.ID, id)
			}
		}
	}

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxVaultSize {
		return fmt.Errorf("vault is too large (%d bytes, max %d)", len(b), MaxVaultSize)
	}
	return nil
}

func validateKey(k *Key) error {
	if k.Alias == "" {
		return fmt.Errorf("key %q has an empty alias", k.ID)
	}
	if err := validateFilename(k.Filename, true); err != nil {
		return fmt.Errorf("key %q: %w", k.ID, err)
	}
	switch k.Kind {
	case KeyKindKeypair, KeyKindCertificate, KeyKindPublic:
	default:
		return fmt.Errorf("key %q has invalid kind %q", k.ID, k.Kind)
	}
	if k.PublicKey == "" && k.PrivateKey == "" && k.Certificate == "" {
		return fmt.Errorf("key %q has no key material", k.ID)
	}
	for name, s := range map[string]string{
		"public key": k.PublicKey, "private key": k.PrivateKey, "certificate": k.Certificate,
	} {
		if len(s) > MaxKeyField {
			return fmt.Errorf("key %q: %s is too large", k.ID, name)
		}
	}
	if err := validateTags(k.Tags); err != nil {
		return fmt.Errorf("key %q: %w", k.ID, err)
	}
	if len(k.Comment) > MaxDescription {
		return fmt.Errorf("key %q: comment is too long", k.ID)
	}
	return nil
}

func validateHost(h *Host) error {
	if len(h.Patterns) == 0 {
		return fmt.Errorf("host %q has no patterns", h.ID)
	}
	if len(h.Patterns) > MaxPatterns {
		return fmt.Errorf("host %q has too many patterns", h.ID)
	}
	for _, p := range h.Patterns {
		if err := validatePattern(p); err != nil {
			return fmt.Errorf("host %q: %w", h.ID, err)
		}
	}
	if strings.ContainsAny(h.HostName, " \t\r\n\x00") {
		return fmt.Errorf("host %q has an invalid hostname", h.ID)
	}
	if len(h.HostName) > 255 {
		return fmt.Errorf("host %q hostname is too long", h.ID)
	}
	if strings.ContainsAny(h.User, " \t\r\n\x00") || len(h.User) > 128 {
		return fmt.Errorf("host %q has an invalid user", h.ID)
	}
	if h.Port < 0 || h.Port > 65535 {
		return fmt.Errorf("host %q has an invalid port", h.ID)
	}
	if len(h.IdentityKeyIDs) > MaxIdentityKeys {
		return fmt.Errorf("host %q has too many identity keys", h.ID)
	}
	if len(h.Options) > MaxHostOptions {
		return fmt.Errorf("host %q has too many advanced options", h.ID)
	}
	for _, o := range h.Options {
		if !optionPattern.MatchString(o.Name) {
			return fmt.Errorf("host %q has invalid option name %q", h.ID, o.Name)
		}
		if forbiddenOptionNames[strings.ToLower(o.Name)] {
			return fmt.Errorf("host %q: option %q must be set in the dedicated field", h.ID, o.Name)
		}
		if len(o.Value) > MaxOptionValue || strings.ContainsAny(o.Value, "\r\n\x00") {
			return fmt.Errorf("host %q has an invalid value for option %q", h.ID, o.Name)
		}
	}
	return nil
}

func validatePattern(p string) error {
	if p == "" || len(p) > 255 {
		return fmt.Errorf("invalid host pattern")
	}
	for _, r := range p {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '#' || r == '"' || r == '\'' {
			return fmt.Errorf("invalid host pattern %q", p)
		}
	}
	return nil
}

func validateFile(f *File) error {
	if err := validateFilename(f.Filename, false); err != nil {
		return fmt.Errorf("file %q: %w", f.ID, err)
	}
	switch f.Encoding {
	case EncodingUTF8:
		if !utf8.ValidString(f.Content) {
			return fmt.Errorf("file %q is marked as UTF-8 but contains invalid bytes", f.ID)
		}
	case EncodingBase64:
		if _, err := base64.StdEncoding.DecodeString(f.Content); err != nil {
			return fmt.Errorf("file %q has invalid base64 content", f.ID)
		}
	default:
		return fmt.Errorf("file %q has invalid encoding %q", f.ID, f.Encoding)
	}
	if len(f.Content) > MaxFileContent {
		return fmt.Errorf("file %q is too large", f.ID)
	}
	if f.Mode != 0o600 && f.Mode != 0o640 && f.Mode != 0o644 {
		return fmt.Errorf("file %q has invalid mode %o", f.ID, f.Mode)
	}
	if err := validateTags(f.Tags); err != nil {
		return fmt.Errorf("file %q: %w", f.ID, err)
	}
	if len(f.Description) > MaxDescription {
		return fmt.Errorf("file %q description is too long", f.ID)
	}
	return nil
}

func validateTags(tags []string) error {
	if len(tags) > MaxTags {
		return fmt.Errorf("too many tags (max %d)", MaxTags)
	}
	for _, t := range tags {
		if len(t) > MaxTagLength {
			return fmt.Errorf("tag %q is too long", t)
		}
		if strings.ContainsAny(t, "\r\n\x00") {
			return fmt.Errorf("tag %q contains invalid characters", t)
		}
	}
	return nil
}

func validateFilename(name string, isKey bool) error {
	if name == "" {
		return fmt.Errorf("empty filename")
	}
	if !filenamePattern.MatchString(name) {
		return fmt.Errorf("invalid filename %q", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid filename %q", name)
	}
	lower := strings.ToLower(name)
	if reservedForAll[lower] || strings.HasPrefix(lower, ".sshvault") {
		return fmt.Errorf("filename %q is reserved", name)
	}
	if isKey {
		if reservedForKey[lower] {
			return fmt.Errorf("filename %q is reserved for a regular file", name)
		}
		if strings.HasSuffix(lower, ".pub") || strings.HasSuffix(lower, "-cert.pub") {
			return fmt.Errorf("key filename %q must not include .pub or -cert.pub", name)
		}
	}
	return nil
}

// CheckFilename exposes filename validation to the import engine.
func CheckFilename(name string, isKey bool) error {
	return validateFilename(name, isKey)
}

func validateUniqueNames(v *Vault) error {
	used := map[string]string{}
	claim := func(name, owner string) error {
		key := strings.ToLower(name)
		if prev, ok := used[key]; ok {
			return fmt.Errorf("filename %q is used by both %s and %s", name, prev, owner)
		}
		used[key] = owner
		return nil
	}
	for _, k := range v.Keys {
		owner := "key " + k.Alias
		for _, n := range []string{k.Filename, k.Filename + ".pub", k.Filename + "-cert.pub"} {
			if err := claim(n, owner); err != nil {
				return err
			}
		}
	}
	for _, f := range v.Files {
		if err := claim(f.Filename, "file "+f.Filename); err != nil {
			return err
		}
	}
	return nil
}

func validateUniqueHostPatterns(v *Vault) error {
	seen := map[string]string{}
	for _, h := range v.Hosts {
		for _, p := range h.Patterns {
			key := strings.ToLower(p)
			if prev, ok := seen[key]; ok {
				return fmt.Errorf("host pattern %q is used by both %s and %s", p, prev, h.ID)
			}
			seen[key] = h.ID
		}
	}
	return nil
}

func (f *File) ContentBytes() ([]byte, error) {
	if f.Encoding == EncodingBase64 {
		return base64.StdEncoding.DecodeString(f.Content)
	}
	return []byte(f.Content), nil
}

func (f *File) SetContentBytes(b []byte) {
	if utf8.Valid(b) && !containsNUL(b) {
		f.Encoding = EncodingUTF8
		f.Content = string(b)
		return
	}
	f.Encoding = EncodingBase64
	f.Content = base64.StdEncoding.EncodeToString(b)
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func SizeLimitError(kind string, size, max int) error {
	return fmt.Errorf("%s is too large (%d bytes, max %d)", kind, size, max)
}
