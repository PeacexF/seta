package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
)

// dnssecState is what the zone and its parent publish.
type dnssecState struct {
	apex bool
	ds   []*dns.DS
	keys []*dns.DNSKEY
	// keySigs and soaSigs are the RRSIGs over the DNSKEY and SOA sets.
	keySigs, soaSigs []*dns.RRSIG
	soa              []dns.RR
}

func loadDNSSEC(ctx context.Context, env core.Env, zone string) (*dnssecState, error) {
	return core.Memoize(ctx, env.Memo, "dns.dnssec:"+zone, func(ctx context.Context) (*dnssecState, error) {
		st := &dnssecState{}
		sec, ok := env.Resolver.(dnsx.DNSSECResolver)
		if !ok {
			return nil, errors.New("the resolver does not support DNSSEC queries")
		}
		// With checking disabled, so that a zone whose DNSSEC is broken (and
		// SERVFAILs for validating resolvers) can still be examined.
		soa, err := sec.LookupDNSSEC(ctx, zone, dns.TypeSOA)
		if err != nil {
			return nil, err
		}
		st.soa, st.soaSigs = soa.Records(), soa.RRSIGs()
		for _, rr := range st.soa {
			st.apex = st.apex || strings.EqualFold(rr.Header().Name, dnsx.CanonicalName(zone))
		}
		if !st.apex {
			return st, nil
		}
		ds, err := sec.LookupDNSSEC(ctx, zone, dns.TypeDS)
		if err != nil {
			return nil, err
		}
		for _, rr := range ds.Records() {
			st.ds = append(st.ds, rr.(*dns.DS))
		}
		keys, err := sec.LookupDNSSEC(ctx, zone, dns.TypeDNSKEY)
		if err != nil {
			return nil, err
		}
		for _, rr := range keys.Records() {
			st.keys = append(st.keys, rr.(*dns.DNSKEY))
		}
		st.keySigs = keys.RRSIGs()
		return st, nil
	})
}

func keyRRs(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// errUnsupported marks signatures whose algorithm Seta can't verify, so no
// verdict is given rather than a false "invalid".
var errUnsupported = errors.New("unsupported algorithm")

// verifySet checks that some signature in sigs, made by one of keys, is valid
// for rrset at now.
func verifySet(sigs []*dns.RRSIG, keys []*dns.DNSKEY, rrset []dns.RR, now time.Time) error {
	if len(sigs) == 0 {
		return errors.New("no signatures")
	}
	var problems []string
	unsupported := true
	for _, sig := range sigs {
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			err := sig.Verify(k, rrset)
			if errors.Is(err, dns.ErrAlg) {
				continue
			}
			unsupported = false
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("signature by key %d doesn't verify: %v", sig.KeyTag, err))
			case !sig.ValidityPeriod(now):
				problems = append(problems, fmt.Sprintf("signature by key %d is valid from %s to %s",
					sig.KeyTag, dns.TimeToString(sig.Inception), dns.TimeToString(sig.Expiration)))
			default:
				return nil
			}
		}
	}
	if unsupported && len(problems) == 0 {
		for _, sig := range sigs {
			if slices.ContainsFunc(keys, func(k *dns.DNSKEY) bool { return k.KeyTag() == sig.KeyTag }) {
				return errUnsupported
			}
		}
		return fmt.Errorf("no DNSKEY matches the signatures' key tags %s", sigTags(sigs))
	}
	return errors.New(strings.Join(problems, "; "))
}

func sigTags(sigs []*dns.RRSIG) string {
	var tags []string
	for _, s := range sigs {
		tags = append(tags, strconv.Itoa(int(s.KeyTag)))
	}
	return strings.Join(tags, ", ")
}

// validate returns why the zone's DNSSEC is broken, or nil. It follows the
// chain a validating resolver builds from the parent's DS records: a DS must
// match a DNSKEY, that key must sign the DNSKEY set, and the DNSKEY set must
// sign the zone's records (checked on the SOA).
func (st *dnssecState) validate(now time.Time) (problem string, err error) {
	if len(st.keys) == 0 {
		return "the parent zone publishes DS records but the zone has no DNSKEY records", nil
	}
	if len(st.keySigs) == 0 && len(st.soaSigs) == 0 {
		// A signed zone always returns signatures; their absence more
		// likely means the resolver strips them.
		return "", errors.New("the resolver returned DNSKEY records without any signatures; it may strip DNSSEC data (try --resolver doh)")
	}
	var anchors []*dns.DNSKEY
	unknownDigest := false
	for _, ds := range st.ds {
		for _, k := range st.keys {
			if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
				continue
			}
			d := k.ToDS(ds.DigestType)
			unknownDigest = unknownDigest || d == nil
			if d != nil && strings.EqualFold(d.Digest, ds.Digest) {
				anchors = append(anchors, k)
			}
		}
	}
	if len(anchors) == 0 && unknownDigest {
		return "", nil
	}
	if len(anchors) == 0 {
		var tags []string
		for _, ds := range st.ds {
			tags = append(tags, strconv.Itoa(int(ds.KeyTag)))
		}
		return fmt.Sprintf("no DNSKEY matches the parent's DS records (key tags %s): a key rollover or DNS provider change left a stale DS", strings.Join(tags, ", ")), nil
	}
	switch err := verifySet(st.keySigs, anchors, keyRRs(st.keys), now); {
	case errors.Is(err, errUnsupported):
		return "", nil
	case err != nil:
		return "DNSKEY set: " + err.Error(), nil
	}
	switch err := verifySet(st.soaSigs, st.keys, st.soa, now); {
	case errors.Is(err, errUnsupported):
		return "", nil
	case err != nil:
		return "SOA: " + err.Error(), nil
	}
	return "", nil
}

// Algorithms and DS digests RFC 8624 says must not or should not be used.
var (
	weakAlgorithms = map[uint8]bool{dns.RSAMD5: true, dns.DSA: true, dns.RSASHA1: true, dns.DSANSEC3SHA1: true, dns.RSASHA1NSEC3SHA1: true, dns.ECCGOST: true}
	weakDigests    = map[uint8]bool{dns.SHA1: true, dns.GOST94: true}
)

func init() {
	set.Define(core.Meta{
		ID:    "dns.dnssec.missing",
		Title: "Domain is not signed with DNSSEC",
		Description: "The zone isn't protected by DNSSEC (no DS record at the parent), so resolvers can't detect " +
			"forged answers from cache poisoning or on-path attackers. When the zone is signed but the parent " +
			"has no DS record, the signatures are never checked.",
		Remediation: "Enable DNSSEC signing at your DNS provider, then publish the DS record it gives you at your " +
			"registrar. Most managed DNS providers do both in one click.",
		Mode:       core.Passive,
		Severity:   core.SeverityLow,
		References: []string{rfc(4033, ""), "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		st, err := loadDNSSEC(ctx, env, t.Name)
		if err != nil || !st.apex || len(st.ds) > 0 {
			return nil, err
		}
		ev := map[string]string{"ds": "none"}
		if len(st.keys) > 0 {
			ev["dnskey"] = fmt.Sprintf("%d keys published, but not delegated from the parent zone", len(st.keys))
		}
		return []core.Finding{{Evidence: ev}}, nil
	})

	set.Define(core.Meta{
		ID:    "dns.dnssec.invalid",
		Title: "DNSSEC validation fails",
		Description: "The parent zone says the domain is signed (DS record), but the signatures don't validate: " +
			"no key matches the DS, a signature doesn't verify, or signatures have expired. Validating resolvers " +
			"(Google, Cloudflare, Quad9 and many ISPs) then answer SERVFAIL, so the domain, its website and its " +
			"mail are unreachable for a large share of users.",
		Remediation: "Fix the chain at the DNS provider (re-enable signing, or finish the key rollover) and make the " +
			"DS record at the registrar match the current key. If signing can't be fixed quickly, remove the DS " +
			"record at the registrar to go back to an unsigned zone.",
		Mode:       core.Passive,
		Severity:   core.SeverityCritical,
		References: []string{rfc(4035, "5"), "https://dnsviz.net/"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		st, err := loadDNSSEC(ctx, env, t.Name)
		if err != nil || !st.apex || len(st.ds) == 0 {
			return nil, err
		}
		problem, err := st.validate(env.Now())
		if err != nil || problem == "" {
			return nil, err
		}
		return []core.Finding{{Evidence: map[string]string{"problem": problem}}}, nil
	})

	set.Define(core.Meta{
		ID:    "dns.dnssec.weak_algorithm",
		Title: "DNSSEC uses a deprecated algorithm",
		Description: "The zone is signed with an algorithm RFC 8624 says must not or should not be used for " +
			"signing (RSA/SHA-1, DSA, RSA/MD5, GOST), or the parent's DS uses a SHA-1 digest. Some validators " +
			"already treat such zones as unsigned.",
		Remediation: "Roll the zone over to ECDSA P-256 with SHA-256 (algorithm 13) and publish a SHA-256 DS (digest type 2).",
		Mode:        core.Passive,
		Severity:    core.SeverityLow,
		References:  []string{rfc(8624, "3.1")},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		st, err := loadDNSSEC(ctx, env, t.Name)
		if err != nil || !st.apex || len(st.ds) == 0 {
			return nil, err
		}
		var weak []string
		for _, k := range st.keys {
			if weakAlgorithms[k.Algorithm] {
				weak = append(weak, fmt.Sprintf("DNSKEY %d: %s", k.KeyTag(), dns.AlgorithmToString[k.Algorithm]))
			}
		}
		for _, ds := range st.ds {
			if weakDigests[ds.DigestType] {
				weak = append(weak, fmt.Sprintf("DS %d: %s digest", ds.KeyTag, dns.HashToString[ds.DigestType]))
			}
		}
		if len(weak) == 0 {
			return nil, nil
		}
		slices.Sort(weak)
		return []core.Finding{{Evidence: map[string]string{"weak": strings.Join(slices.Compact(weak), "; ")}}}, nil
	})
}
