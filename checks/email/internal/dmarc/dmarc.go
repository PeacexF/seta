// Package dmarc parses DMARC policy records (RFC 7489).
package dmarc

import (
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/tags"
)

type Policy string

const (
	None       Policy = "none"
	Quarantine Policy = "quarantine"
	Reject     Policy = "reject"
)

type URI struct {
	Raw    string
	Scheme string
	// Address and Domain are set for mailto: URIs.
	Address string
	Domain  string
}

type Record struct {
	Raw string
	P   Policy
	// ImplicitP is set when p= was absent and treated as none because a
	// valid rua= exists (RFC 7489 §6.6.3).
	ImplicitP bool
	SP        Policy // empty when absent
	Pct       int
	RUA, RUF  []URI
	ADKIM     string
	ASPF      string
}

// IsDMARC reports whether txt starts with the v=DMARC1 tag; other TXT
// records at _dmarc are ignored during discovery (RFC 7489 §6.6.3).
func IsDMARC(txt string) bool {
	first, _, _ := strings.Cut(txt, ";")
	name, value, ok := strings.Cut(first, "=")
	return ok && strings.TrimSpace(name) == "v" && strings.EqualFold(strings.TrimSpace(value), "DMARC1")
}

func Parse(txt string) (*Record, error) {
	if !IsDMARC(txt) {
		return nil, errors.New("record does not start with v=DMARC1")
	}
	list, err := tags.Parse(txt, true)
	if err != nil {
		return nil, err
	}
	r := &Record{Raw: txt, Pct: 100, ADKIM: "r", ASPF: "r"}
	for _, t := range list[1:] {
		v := t.Value
		switch t.Name {
		case "p", "sp":
			p, err := parsePolicy(v)
			if err != nil {
				return nil, fmt.Errorf("%s=%s: %w", t.Name, v, err)
			}
			if t.Name == "p" {
				r.P = p
			} else {
				r.SP = p
			}
		case "pct":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 100 {
				return nil, fmt.Errorf("pct=%s: want an integer from 0 to 100", v)
			}
			r.Pct = n
		case "rua", "ruf":
			uris, err := parseURIs(v)
			if err != nil {
				return nil, fmt.Errorf("%s=%s: %w", t.Name, v, err)
			}
			if t.Name == "rua" {
				r.RUA = uris
			} else {
				r.RUF = uris
			}
		case "adkim", "aspf":
			if v != "r" && v != "s" {
				return nil, fmt.Errorf("%s=%s: want r or s", t.Name, v)
			}
			if t.Name == "adkim" {
				r.ADKIM = v
			} else {
				r.ASPF = v
			}
		case "fo":
			for o := range strings.SplitSeq(v, ":") {
				if o = strings.TrimSpace(o); o != "0" && o != "1" && o != "d" && o != "s" {
					return nil, fmt.Errorf("fo=%s: options are 0, 1, d and s", v)
				}
			}
		case "ri":
			if _, err := strconv.ParseUint(v, 10, 32); err != nil {
				return nil, fmt.Errorf("ri=%s: want a number of seconds", v)
			}
		case "v":
			return nil, errors.New("v= must appear only once, first")
		}
		// Unknown tags must be ignored (RFC 7489 §6.3).
	}
	if r.P == "" {
		if len(r.RUA) == 0 {
			return nil, errors.New("missing required p= tag")
		}
		r.P, r.ImplicitP = None, true
	}
	return r, nil
}

func parsePolicy(v string) (Policy, error) {
	switch p := Policy(strings.ToLower(v)); p {
	case None, Quarantine, Reject:
		return p, nil
	}
	return "", errors.New("want none, quarantine or reject")
}

func parseURIs(v string) ([]URI, error) {
	var out []URI
	for raw := range strings.SplitSeq(v, ",") {
		raw = strings.TrimSpace(raw)
		scheme, rest, ok := strings.Cut(raw, ":")
		if !ok || scheme == "" || rest == "" {
			return nil, fmt.Errorf("%q is not a URI", raw)
		}
		u := URI{Raw: raw, Scheme: strings.ToLower(scheme)}
		if u.Scheme == "mailto" {
			addr := rest
			if i := strings.LastIndexByte(addr, '!'); i >= 0 {
				if !validSize(addr[i+1:]) {
					return nil, fmt.Errorf("%q has an invalid size limit", raw)
				}
				addr = addr[:i]
			}
			parsed, err := mail.ParseAddress(addr)
			if err != nil || parsed.Name != "" {
				return nil, fmt.Errorf("%q is not a valid mailto address", raw)
			}
			u.Address = parsed.Address
			_, domain, _ := strings.Cut(parsed.Address, "@")
			u.Domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		}
		out = append(out, u)
	}
	return out, nil
}

// validSize checks a "!10m"-style limit: digits with an optional k/m/g/t unit.
func validSize(s string) bool {
	s = strings.TrimRight(strings.ToLower(s), "kmgt")
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}
