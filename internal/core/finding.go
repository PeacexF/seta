package core

import (
	"crypto/sha256"
	"encoding/hex"
)

// Finding is a single problem a check found on a target.
type Finding struct {
	CheckID string
	Target  string
	// Subject is the specific thing within the target the finding is about,
	// e.g. "mx2.example.com" or "selector:s1". Empty for domain-level findings.
	// Checks must build subjects deterministically, since they are part of
	// the fingerprint.
	Subject  string
	Severity Severity
	Title    string
	// Evidence holds raw facts supporting the finding (the record text, a
	// lookup count, a certificate expiry). It is never fingerprinted, so
	// rewording or new evidence does not turn a finding into a "new" one.
	Evidence    map[string]string
	Remediation string
	// References default to the check's Meta.References.
	References []string
}

// Fingerprint returns a stable identifier for the finding derived only from
// its check ID, target, and subject.
func (f Finding) Fingerprint() string {
	return Fingerprint(f.CheckID, f.Target, f.Subject)
}

// Fingerprint hashes check ID, target, and subject into a stable 32-character
// hex string. The fields are NUL-separated so that no two distinct triples
// can produce the same input.
func Fingerprint(checkID, target, subject string) string {
	h := sha256.New()
	h.Write([]byte(checkID))
	h.Write([]byte{0})
	h.Write([]byte(target))
	h.Write([]byte{0})
	h.Write([]byte(subject))
	return hex.EncodeToString(h.Sum(nil)[:16])
}
