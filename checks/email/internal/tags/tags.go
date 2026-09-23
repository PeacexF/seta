// Package tags parses tag=value lists (RFC 6376 §3.2), the syntax shared by
// DKIM keys, DMARC, MTA-STS and TLS-RPT records.
package tags

import (
	"fmt"
	"strings"
)

type Tag struct {
	Name  string
	Value string
}

type List []Tag

// Parse splits s on ";" into tags. Surrounding whitespace is trimmed, a
// trailing ";" is allowed, and duplicate names are an error. With fold set,
// names are compared and returned in lowercase.
func Parse(s string, fold bool) (List, error) {
	var out List
	seen := make(map[string]bool)
	parts := strings.Split(s, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			if i == len(parts)-1 {
				break
			}
			return nil, fmt.Errorf("empty tag")
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("tag %q has no '='", part)
		}
		name = strings.TrimSpace(name)
		if !validName(name) {
			return nil, fmt.Errorf("invalid tag name %q", name)
		}
		if fold {
			name = strings.ToLower(name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		seen[name] = true
		out = append(out, Tag{Name: name, Value: strings.TrimSpace(value)})
	}
	return out, nil
}

func validName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isAlpha(s[i]) && !(s[i] >= '0' && s[i] <= '9') && s[i] != '_' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func (l List) Get(name string) (string, bool) {
	for _, t := range l {
		if t.Name == name {
			return t.Value, true
		}
	}
	return "", false
}
