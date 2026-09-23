// Package dkim parses DKIM public key records (RFC 6376 §3.6.1, RFC 8463).
package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/tags"
)

type Key struct {
	Type    string // rsa or ed25519
	Revoked bool   // empty p=
	Bits    int
	Testing bool // t=y
}

// IsKey reports whether txt looks like a DKIM key record. v= is optional,
// so the p= tag is what identifies one.
func IsKey(txt string) bool {
	list, err := tags.Parse(txt, false)
	if err != nil {
		return strings.HasPrefix(strings.TrimSpace(txt), "v=DKIM1")
	}
	_, ok := list.Get("p")
	return ok
}

func Parse(txt string) (*Key, error) {
	list, err := tags.Parse(txt, false)
	if err != nil {
		return nil, err
	}
	for i, t := range list {
		if t.Name == "v" && (i != 0 || t.Value != "DKIM1") {
			return nil, errors.New("v= must be first and equal DKIM1")
		}
	}
	k := &Key{Type: "rsa"}
	if v, ok := list.Get("k"); ok {
		k.Type = v
	}
	if v, ok := list.Get("t"); ok {
		for f := range strings.SplitSeq(v, ":") {
			if strings.TrimSpace(f) == "y" {
				k.Testing = true
			}
		}
	}
	p, ok := list.Get("p")
	if !ok {
		return nil, errors.New("missing p= tag")
	}
	p = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, p)
	if p == "" {
		k.Revoked = true
		return k, nil
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, fmt.Errorf("p= is not valid base64: %w", err)
	}

	switch k.Type {
	case "rsa":
		pub, err := parseRSA(der)
		if err != nil {
			return nil, err
		}
		k.Bits = pub.N.BitLen()
	case "ed25519":
		if len(der) != 32 {
			return nil, fmt.Errorf("ed25519 key is %d bytes, want 32", len(der))
		}
		k.Bits = 256
	default:
		return nil, fmt.Errorf("unknown key type k=%s", k.Type)
	}
	return k, nil
}

// parseRSA accepts SubjectPublicKeyInfo as the RFC requires, and bare PKCS#1
// keys, which some providers publish and verifiers accept.
func parseRSA(der []byte) (*rsa.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("k=rsa but p= holds a non-RSA key")
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}
	return nil, errors.New("p= is not a valid RSA public key")
}
