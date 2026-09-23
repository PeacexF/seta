// Package spf parses SPF records (RFC 7208) and measures their DNS cost.
package spf

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Qualifier byte

const (
	Pass     Qualifier = '+'
	Fail     Qualifier = '-'
	SoftFail Qualifier = '~'
	Neutral  Qualifier = '?'
)

type Mechanism struct {
	Qualifier Qualifier
	Kind      string // all, include, a, mx, ptr, ip4, ip6, exists
	Domain    string // domain-spec, possibly with macros; empty means the current domain
	Network   netip.Prefix
	CIDR4     int // -1 when absent
	CIDR6     int
}

func (m Mechanism) String() string {
	q := ""
	if m.Qualifier != Pass {
		q = string(m.Qualifier)
	}
	switch {
	case m.Kind == "ip4" || m.Kind == "ip6":
		return q + m.Kind + ":" + m.Network.String()
	case m.Domain != "":
		return q + m.Kind + ":" + m.Domain
	}
	return q + m.Kind
}

// CountsLookup reports whether the mechanism counts toward the 10-lookup
// limit (RFC 7208 §4.6.4).
func (m Mechanism) CountsLookup() bool {
	switch m.Kind {
	case "include", "a", "mx", "ptr", "exists":
		return true
	}
	return false
}

type Record struct {
	Raw        string
	Mechanisms []Mechanism
	Redirect   string
	Exp        string
}

// All returns the record's "all" mechanism, if any.
func (r *Record) All() (Mechanism, bool) {
	for _, m := range r.Mechanisms {
		if m.Kind == "all" {
			return m, true
		}
	}
	return Mechanism{}, false
}

// IsSPF reports whether a TXT string is an SPF record: "v=spf1" followed by
// a space or nothing, case-insensitively (RFC 7208 §4.5).
func IsSPF(txt string) bool {
	if len(txt) < 6 || !strings.EqualFold(txt[:6], "v=spf1") {
		return false
	}
	return len(txt) == 6 || txt[6] == ' '
}

func Parse(txt string) (*Record, error) {
	if !IsSPF(txt) {
		return nil, errors.New("record does not start with v=spf1")
	}
	rec := &Record{Raw: txt}
	for term := range strings.FieldsSeq(txt[6:]) {
		if name, value, ok := splitModifier(term); ok {
			if err := rec.addModifier(strings.ToLower(name), value); err != nil {
				return nil, err
			}
			continue
		}
		m, err := parseMechanism(term)
		if err != nil {
			return nil, err
		}
		rec.Mechanisms = append(rec.Mechanisms, m)
	}
	return rec, nil
}

func splitModifier(term string) (name, value string, ok bool) {
	i := 0
	for i < len(term) && (isAlpha(term[i]) || i > 0 && (isDigit(term[i]) || strings.IndexByte("-_.", term[i]) >= 0)) {
		i++
	}
	if i == 0 || i >= len(term) || term[i] != '=' {
		return "", "", false
	}
	return term[:i], term[i+1:], true
}

func (r *Record) addModifier(name, value string) error {
	switch name {
	case "redirect", "exp":
		if (name == "redirect" && r.Redirect != "") || (name == "exp" && r.Exp != "") {
			return fmt.Errorf("%s= appears more than once", name)
		}
		if err := validateDomainSpec(value, name == "exp"); err != nil {
			return fmt.Errorf("%s=%s: %w", name, value, err)
		}
		if name == "redirect" {
			r.Redirect = value
		} else {
			r.Exp = value
		}
		return nil
	}
	if _, err := parseMacroString(value, false); err != nil {
		return fmt.Errorf("modifier %s=%s: %w", name, value, err)
	}
	return nil
}

func parseMechanism(term string) (Mechanism, error) {
	m := Mechanism{Qualifier: Pass, CIDR4: -1, CIDR6: -1}
	rest := term
	if q := Qualifier(rest[0]); q == Pass || q == Fail || q == SoftFail || q == Neutral {
		m.Qualifier = q
		rest = rest[1:]
	}
	end := strings.IndexAny(rest, ":/")
	if end < 0 {
		end = len(rest)
	}
	m.Kind = strings.ToLower(rest[:end])
	arg := rest[end:]

	switch m.Kind {
	case "all":
		if arg != "" {
			return m, fmt.Errorf("%q: all takes no arguments", term)
		}
	case "include", "exists":
		ds, ok := strings.CutPrefix(arg, ":")
		if !ok || ds == "" {
			return m, fmt.Errorf("%q: %s requires a domain", term, m.Kind)
		}
		if err := validateDomainSpec(ds, false); err != nil {
			return m, fmt.Errorf("%q: %w", term, err)
		}
		m.Domain = ds
	case "a", "mx", "ptr":
		ds, cidr := arg, ""
		if i := strings.IndexByte(arg, '/'); i >= 0 {
			ds, cidr = arg[:i], arg[i:]
		}
		if ds != "" {
			ds, ok := strings.CutPrefix(ds, ":")
			if !ok || ds == "" {
				return m, fmt.Errorf("%q: malformed domain", term)
			}
			if err := validateDomainSpec(ds, false); err != nil {
				return m, fmt.Errorf("%q: %w", term, err)
			}
			m.Domain = ds
		}
		if cidr != "" {
			if m.Kind == "ptr" {
				return m, fmt.Errorf("%q: ptr takes no CIDR length", term)
			}
			if err := m.parseDualCIDR(cidr); err != nil {
				return m, fmt.Errorf("%q: %w", term, err)
			}
		}
	case "ip4", "ip6":
		v, ok := strings.CutPrefix(arg, ":")
		if !ok || v == "" {
			return m, fmt.Errorf("%q: %s requires an address", term, m.Kind)
		}
		p, err := parseNetwork(v, m.Kind == "ip4")
		if err != nil {
			return m, fmt.Errorf("%q: %w", term, err)
		}
		m.Network = p
	default:
		return m, fmt.Errorf("%q: unknown mechanism %q", term, m.Kind)
	}
	return m, nil
}

// parseDualCIDR handles "/24", "//64" and "/24//64".
func (m *Mechanism) parseDualCIDR(s string) error {
	v4, v6, dual := strings.Cut(s, "//")
	if !dual {
		v4 = s
	}
	if v4 != "" {
		n, err := parseCIDRLen(strings.TrimPrefix(v4, "/"), 32)
		if err != nil || !strings.HasPrefix(v4, "/") {
			return fmt.Errorf("invalid IPv4 CIDR length %q", v4)
		}
		m.CIDR4 = n
	}
	if dual {
		n, err := parseCIDRLen(v6, 128)
		if err != nil {
			return fmt.Errorf("invalid IPv6 CIDR length %q", v6)
		}
		m.CIDR6 = n
	}
	return nil
}

func parseCIDRLen(s string, max int) (int, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, errors.New("bad length")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > max {
		return 0, errors.New("bad length")
	}
	return n, nil
}

func parseNetwork(s string, v4 bool) (netip.Prefix, error) {
	addr, length, hasLen := strings.Cut(s, "/")
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q", addr)
	}
	if v4 && !a.Is4() || !v4 && !a.Is6() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv%s address", addr, map[bool]string{true: "4", false: "6"}[v4])
	}
	bits := a.BitLen()
	if hasLen {
		n, err := parseCIDRLen(length, a.BitLen())
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR length %q", length)
		}
		bits = n
	}
	return netip.PrefixFrom(a, bits), nil
}

// validateDomainSpec checks domain-spec = macro-string domain-end, where
// domain-end is "." toplabel or a macro (RFC 7208 §7.1). A purely numeric
// last label is rejected, which catches "include:192.0.2.1".
func validateDomainSpec(ds string, exp bool) error {
	endsWithMacro, err := parseMacroString(ds, exp)
	if err != nil {
		return err
	}
	if endsWithMacro {
		return nil
	}
	name := strings.TrimSuffix(ds, ".")
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return fmt.Errorf("%q is not a fully qualified domain", ds)
	}
	if !validTopLabel(name[i+1:]) {
		return fmt.Errorf("%q does not end in a valid top-level label", ds)
	}
	return nil
}

func validTopLabel(l string) bool {
	if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	hasAlpha := false
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case isAlpha(c):
			hasAlpha = true
		case isDigit(c), c == '-':
		default:
			return false
		}
	}
	return hasAlpha || strings.Contains(l, "-")
}

// parseMacroString validates macro syntax (RFC 7208 §7.1) and reports whether
// the string ends with a macro expansion.
func parseMacroString(s string, exp bool) (endsWithMacro bool, err error) {
	letters := "slodiphv"
	if exp {
		letters += "crt"
	}
	for i := 0; i < len(s); {
		c := s[i]
		if c != '%' {
			if c < 0x21 || c > 0x7e {
				return false, fmt.Errorf("invalid character %q", c)
			}
			endsWithMacro = false
			i++
			continue
		}
		if i+1 >= len(s) {
			return false, errors.New("dangling '%'")
		}
		switch s[i+1] {
		case '%', '_', '-':
			endsWithMacro = false
			i += 2
			continue
		case '{':
		default:
			return false, fmt.Errorf("invalid macro %q", s[i:i+2])
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return false, errors.New("unterminated macro")
		}
		body := s[i+2 : i+end]
		if body == "" || strings.IndexByte(letters, lower(body[0])) < 0 {
			return false, fmt.Errorf("invalid macro letter in %q", s[i:i+end+1])
		}
		j := 1
		for j < len(body) && isDigit(body[j]) {
			j++
		}
		if j < len(body) && lower(body[j]) == 'r' {
			j++
		}
		for ; j < len(body); j++ {
			if strings.IndexByte(".-+,/_=", body[j]) < 0 {
				return false, fmt.Errorf("invalid macro transformer in %q", s[i:i+end+1])
			}
		}
		endsWithMacro = true
		i += end + 1
	}
	return endsWithMacro, nil
}

// HasMacro reports whether a domain-spec needs sender data to expand, which
// Seta cannot know, so such terms are counted but not followed.
func HasMacro(ds string) bool { return strings.Contains(ds, "%{") }

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
