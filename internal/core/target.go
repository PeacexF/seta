package core

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// TargetKind identifies what sort of thing a target is.
type TargetKind string

// KindDomain is a registrable domain or subdomain, e.g. "example.com".
const KindDomain TargetKind = "domain"

// Target is something to check. Name is always in canonical form (see
// ParseDomain), so it can be used directly in fingerprints.
type Target struct {
	Kind  TargetKind
	Name  string
	Email EmailOptions
	// Plugins holds each plugin's JSON config for this target, by plugin name.
	Plugins map[string][]byte
}

type EmailOptions struct {
	DKIMSelectors []string
	// SelectorsGuessed marks DKIMSelectors as common guesses rather than the
	// domain's real selectors, so finding none proves nothing.
	SelectorsGuessed bool
	// ExpectedMX lists the MX hosts the domain should have; a leading "*."
	// matches one label. Empty disables email.mx.unexpected.
	ExpectedMX []string
	// DNSBLs overrides the default blocklist zones.
	DNSBLs []string
	// SpamhausDQSKey enables Spamhaus via Data Query Service, which unlike
	// the public mirrors answers queries relayed through public resolvers.
	SpamhausDQSKey string
}

func (t Target) String() string { return t.Name }

// idnaProfile converts internationalized names to their ASCII (punycode) form
// without the hostname-only rules that would reject DNS labels like "_dmarc".
var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false))

// ParseDomain validates a user-supplied domain name and returns a domain
// target in canonical form: lowercase, ASCII (punycode), no trailing dot.
func ParseDomain(s string) (Target, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Target{}, fmt.Errorf("empty domain name")
	}
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, "/:@ ") {
		return Target{}, fmt.Errorf("%q is not a domain name (expected something like example.com, not a URL or host:port)", s)
	}
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if !isASCII(name) {
		var err error
		if name, err = idnaProfile.ToASCII(name); err != nil {
			return Target{}, fmt.Errorf("%q is not a valid domain name: %w", s, err)
		}
	}
	if len(name) > 253 {
		return Target{}, fmt.Errorf("%q is not a valid domain name: longer than 253 characters", s)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return Target{}, fmt.Errorf("%q is not a fully qualified domain name (expected something like example.com)", s)
	}
	for _, l := range labels {
		if err := validLabel(l); err != nil {
			return Target{}, fmt.Errorf("%q is not a valid domain name: %w", s, err)
		}
	}
	return Target{Kind: KindDomain, Name: name}, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func validLabel(l string) error {
	if l == "" {
		return fmt.Errorf("empty label")
	}
	if len(l) > 63 {
		return fmt.Errorf("label %q longer than 63 characters", l)
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", l)
	}
	for _, c := range l {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("label %q contains invalid character %q", l, c)
		}
	}
	return nil
}
