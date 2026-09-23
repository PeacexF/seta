// Package mtasts parses MTA-STS records and policies (RFC 8461).
package mtasts

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/tags"
)

const MaxPolicySize = 64 * 1024 // RFC 8461 §3.3

func IsTXT(txt string) bool {
	first, _, _ := strings.Cut(txt, ";")
	name, value, ok := strings.Cut(first, "=")
	return ok && strings.TrimSpace(name) == "v" && strings.TrimSpace(value) == "STSv1"
}

// ParseTXT validates the _mta-sts record and returns its policy id.
func ParseTXT(txt string) (string, error) {
	list, err := tags.Parse(txt, false)
	if err != nil {
		return "", err
	}
	if len(list) == 0 || list[0].Name != "v" || list[0].Value != "STSv1" {
		return "", errors.New("record must start with v=STSv1")
	}
	id, ok := list.Get("id")
	if !ok {
		return "", errors.New("missing id= tag")
	}
	if len(id) < 1 || len(id) > 32 || !alnum(id) {
		return "", fmt.Errorf("id=%s must be 1-32 letters and digits", id)
	}
	return id, nil
}

type Policy struct {
	Mode   string
	MaxAge int
	MX     []string
}

func ParsePolicy(body string) (*Policy, error) {
	p := &Policy{}
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %q is not key: value", line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key != "mx" && seen[key] {
			return nil, fmt.Errorf("duplicate %q field", key)
		}
		seen[key] = true
		switch key {
		case "version":
			if value != "STSv1" {
				return nil, fmt.Errorf("version: %s, want STSv1", value)
			}
		case "mode":
			if value != "enforce" && value != "testing" && value != "none" {
				return nil, fmt.Errorf("mode: %s, want enforce, testing or none", value)
			}
			p.Mode = value
		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 31557600 || len(value) > 10 {
				return nil, fmt.Errorf("max_age: %s, want 0 to 31557600 seconds", value)
			}
			p.MaxAge = n
		case "mx":
			if !validPattern(value) {
				return nil, fmt.Errorf("mx: %q is not a host name or *.domain pattern", value)
			}
			p.MX = append(p.MX, strings.ToLower(strings.TrimSuffix(value, ".")))
		}
	}
	for _, required := range []string{"version", "mode", "max_age"} {
		if !seen[required] {
			return nil, fmt.Errorf("missing %s field", required)
		}
	}
	if p.Mode != "none" && len(p.MX) == 0 {
		return nil, errors.New("missing mx field")
	}
	return p, nil
}

// Match reports whether host matches an mx pattern, where "*." matches
// exactly one leftmost label (RFC 8461 §4.1).
func Match(pattern, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		label, rest, found := strings.Cut(host, ".")
		return found && label != "" && rest == suffix
	}
	return host == pattern
}

func validPattern(p string) bool {
	p = strings.TrimPrefix(strings.TrimSuffix(p, "."), "*.")
	if !strings.Contains(p, ".") {
		return false
	}
	for l := range strings.SplitSeq(p, ".") {
		if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func alnum(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
