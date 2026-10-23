package sshutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"sshvault/internal/vault"
)

const (
	DuplicateActionComment = "comment"
	DuplicateActionRemove  = "remove"
	DuplicateActionSplit   = "split"
)

var (
	ErrConfigChanged     = errors.New("the config changed since the preview")
	ErrDuplicateNotFound = errors.New("duplicate block not found")
	ErrSplitNoPatterns   = errors.New("no non-duplicate patterns remain")
)

// DuplicateItem describes one Host block outside the managed block that
// collides with a deployed vault host.
type DuplicateItem struct {
	ID          string   `json:"id"`
	Patterns    []string `json:"patterns"`
	AllPatterns []string `json:"allPatterns"`
	Mixed       bool     `json:"mixed"`
	External    string   `json:"external"`
	Managed     string   `json:"managed"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
}

type DuplicateReport struct {
	ConfigHash string          `json:"configHash"`
	Items      []DuplicateItem `json:"items"`
}

type duplicateRaw struct {
	item      DuplicateItem
	start     int
	end       int
	patterns  []string
	colliding []string
}

// DuplicateReport finds duplicate Host blocks in the current config.
func (m *Manager) DuplicateReport(hosts []*vault.Host, keys []*vault.Key) (*DuplicateReport, error) {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	content, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	report, _, err := m.duplicatesLocked(content, hosts, keys)
	return report, err
}

// ResolveDuplicate applies one action to one duplicate and returns the new report.
func (m *Manager) ResolveDuplicate(hosts []*vault.Host, keys []*vault.Key, expectedHash, id, action string) (*DuplicateReport, error) {
	switch action {
	case DuplicateActionComment, DuplicateActionRemove, DuplicateActionSplit:
	default:
		return nil, fmt.Errorf("invalid duplicate action %q", action)
	}
	m.configMu.Lock()
	defer m.configMu.Unlock()
	content, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if configHash(content) != expectedHash {
		return nil, ErrConfigChanged
	}
	_, dups, err := m.duplicatesLocked(content, hosts, keys)
	if err != nil {
		return nil, err
	}
	var target *duplicateRaw
	for i := range dups {
		if dups[i].item.ID == id {
			target = &dups[i]
			break
		}
	}
	if target == nil {
		return nil, ErrDuplicateNotFound
	}
	if action == DuplicateActionSplit && !target.item.Mixed {
		return nil, fmt.Errorf("the block has no non-duplicate patterns to preserve")
	}

	lines, err := splitConfigLines(content)
	if err != nil {
		return nil, err
	}
	if target.start < 0 || target.end >= len(lines) || target.start > target.end {
		return nil, ErrDuplicateNotFound
	}

	var next []string
	switch action {
	case DuplicateActionComment:
		eol := lineEnding(lines[target.start])
		next = append(next, lines[:target.start]...)
		next = append(next, "# sshvault: duplicate disabled; the managed block takes precedence"+eol)
		for _, line := range lines[target.start : target.end+1] {
			next = append(next, commentConfigLine(line))
		}
		next = append(next, lines[target.end+1:]...)
	case DuplicateActionRemove:
		next = append(next, lines[:target.start]...)
		next = append(next, lines[target.end+1:]...)
	case DuplicateActionSplit:
		remaining := nonCollidingPatterns(target.patterns, target.colliding)
		if len(remaining) == 0 {
			return nil, ErrSplitNoPatterns
		}
		eol := lineEnding(lines[target.start])
		indent := leadingWhitespace(lines[target.start])
		next = append(next, lines[:target.start]...)
		next = append(next, indent+"# sshvault: duplicate patterns removed: "+strings.Join(target.colliding, " ")+eol)
		next = append(next, indent+"Host "+strings.Join(remaining, " ")+eol)
		next = append(next, lines[target.start+1:]...)
	}

	newContent := strings.Join(next, "")
	targetPath := m.configTarget()
	mode := os.FileMode(0o600)
	if info, err := os.Stat(targetPath); err == nil {
		if info.Mode().Perm() != 0 {
			mode = info.Mode().Perm()
		}
		if err := m.backupFile(targetPath); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := writeAtomic(targetPath, []byte(newContent), mode); err != nil {
		return nil, err
	}
	report, _, err := m.duplicatesLocked(newContent, hosts, keys)
	return report, err
}

func (m *Manager) duplicatesLocked(content string, hosts []*vault.Host, keys []*vault.Key) (*DuplicateReport, []duplicateRaw, error) {
	lines, err := splitConfigLines(content)
	if err != nil {
		return nil, nil, err
	}
	managed, err := managedLineMask(content, lines)
	if err != nil {
		return nil, nil, err
	}
	hostsByPattern := map[string][]*vault.Host{}
	for _, h := range hosts {
		for _, p := range h.Patterns {
			key := strings.ToLower(p)
			hostsByPattern[key] = append(hostsByPattern[key], h)
		}
	}
	keysByID := map[string]*vault.Key{}
	for _, k := range keys {
		keysByID[k.ID] = k
	}
	dups := buildDuplicates(lines, managed, hostsByPattern, keysByID, m.DisplayPath)
	items := make([]DuplicateItem, 0, len(dups))
	for _, d := range dups {
		items = append(items, d.item)
	}
	return &DuplicateReport{ConfigHash: configHash(content), Items: items}, dups, nil
}

func buildDuplicates(lines []string, managed []bool, hostsByPattern map[string][]*vault.Host, keysByID map[string]*vault.Key, display func(string) string) []duplicateRaw {
	var out []duplicateRaw
	for i := 0; i < len(lines); i++ {
		if managed[i] {
			continue
		}
		t := strings.TrimSpace(trimEOL(lines[i]))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		patterns, ok := parseHostLine(t)
		if !ok {
			continue
		}
		end := i
		for j := i + 1; j < len(lines); j++ {
			if managed[j] {
				break
			}
			b := strings.TrimSpace(trimEOL(lines[j]))
			if isTopLevelBoundary(b) {
				break
			}
			if b != "" && !strings.HasPrefix(b, "#") {
				end = j
			}
		}
		var colliding []string
		seen := map[string]bool{}
		for _, p := range patterns {
			p = strings.Trim(p, `"'`)
			if p == "" {
				continue
			}
			key := strings.ToLower(p)
			if len(hostsByPattern[key]) > 0 && !seen[key] {
				seen[key] = true
				colliding = append(colliding, p)
			}
		}
		if len(colliding) > 0 {
			external := strings.Join(lines[i:end+1], "")
			item := DuplicateItem{
				ID:          shortHash(external + "|" + strings.Join(cleanPatterns(patterns), ",")),
				Patterns:    colliding,
				AllPatterns: cleanPatterns(patterns),
				Mixed:       len(colliding) < len(cleanPatterns(patterns)),
				External:    strings.TrimRight(external, "\r\n"),
				Managed:     managedSegments(colliding, hostsByPattern, keysByID, display),
				StartLine:   i + 1,
				EndLine:     end + 1,
			}
			out = append(out, duplicateRaw{item: item, start: i, end: end, patterns: patterns, colliding: colliding})
		}
		i = end
	}
	return out
}

func managedSegments(patterns []string, hostsByPattern map[string][]*vault.Host, keysByID map[string]*vault.Key, display func(string) string) string {
	var segs []string
	seen := map[string]bool{}
	for _, p := range patterns {
		for _, h := range hostsByPattern[strings.ToLower(p)] {
			if seen[h.ID] {
				continue
			}
			seen[h.ID] = true
			segs = append(segs, hostIDPrefix+h.ID+"\n"+RenderHost(h, keysByID, display))
		}
	}
	return strings.Join(segs, "\n\n")
}

func parseHostLine(t string) ([]string, bool) {
	fields := strings.Fields(t)
	if len(fields) == 0 {
		return nil, false
	}
	var patterns []string
	switch {
	case strings.EqualFold(fields[0], "Host"):
		patterns = fields[1:]
	case strings.HasPrefix(strings.ToLower(fields[0]), "host="):
		patterns = append([]string{fields[0][5:]}, fields[1:]...)
	default:
		return nil, false
	}
	return patterns, true
}

func isTopLevelBoundary(t string) bool {
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	fields := strings.Fields(t)
	if len(fields) == 0 {
		return false
	}
	first := strings.ToLower(fields[0])
	return first == "host" || first == "match" || first == "include" || strings.HasPrefix(first, "host=") || strings.HasPrefix(first, "match=")
}

func cleanPatterns(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	seen := map[string]bool{}
	for _, p := range patterns {
		p = strings.Trim(p, `"'`)
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		seen[strings.ToLower(p)] = true
		out = append(out, p)
	}
	return out
}

func nonCollidingPatterns(all, colliding []string) []string {
	blocked := map[string]bool{}
	for _, p := range colliding {
		blocked[strings.ToLower(p)] = true
	}
	var out []string
	for _, p := range all {
		p = strings.Trim(p, `"'`)
		if p == "" || blocked[strings.ToLower(p)] {
			continue
		}
		out = append(out, p)
	}
	return out
}

func splitConfigLines(content string) ([]string, error) {
	if content == "" {
		return nil, nil
	}
	lines := strings.SplitAfter(content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" && strings.HasSuffix(content, "\n") {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}

func managedLineMask(content string, lines []string) ([]bool, error) {
	parsed, err := parseConfig(content)
	if err != nil {
		return nil, err
	}
	mask := make([]bool, len(lines))
	if !parsed.Found {
		return mask, nil
	}
	start, end := -1, -1
	for i, line := range lines {
		t := strings.TrimSpace(trimEOL(line))
		if t == ConfigBeginMarker && start == -1 {
			start = i
		}
		if t == ConfigEndMarker && start != -1 {
			end = i
			break
		}
	}
	if start < 0 || end < start {
		return nil, ErrConfigMarkers
	}
	for i := start; i <= end; i++ {
		mask[i] = true
	}
	return mask, nil
}

func commentConfigLine(line string) string {
	body, eol := trimEOLWithEnding(line)
	if strings.TrimSpace(body) == "" {
		return eol
	}
	if strings.HasPrefix(strings.TrimSpace(body), "#") {
		return line
	}
	return "# " + body + eol
}

func trimEOL(s string) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s
}

func trimEOLWithEnding(s string) (body, eol string) {
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2], "\r\n"
	case strings.HasSuffix(s, "\n"):
		return s[:len(s)-1], "\n"
	default:
		return s, ""
	}
}

func lineEnding(line string) string {
	_, eol := trimEOLWithEnding(line)
	if eol == "" {
		return "\n"
	}
	return eol
}

func leadingWhitespace(line string) string {
	body, _ := trimEOLWithEnding(line)
	idx := 0
	for idx < len(body) && (body[idx] == ' ' || body[idx] == '\t') {
		idx++
	}
	return body[:idx]
}

func configHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
