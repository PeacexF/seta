package dnsx

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Canary is a public record that every honest recursive resolver can answer.
type Canary struct {
	Name string
	Type uint16
}

// canaryDomains are large mail providers whose MX, TXT (SPF) and A records
// have been stable for well over a decade. Each record type only needs one
// of them to answer, so a single provider changing its setup can't break the
// check.
var canaryDomains = []string{"gmail.com", "outlook.com", "yahoo.com"}

// canaryTypes are the record types checks depend on most. Some networks
// answer A queries honestly while blanking everything else, so each type is
// probed separately.
var canaryTypes = []uint16{dns.TypeA, dns.TypeMX, dns.TypeTXT}

// Canaries lists every query Probe makes.
func Canaries() []Canary {
	var out []Canary
	for _, t := range canaryTypes {
		for _, d := range canaryDomains {
			out = append(out, Canary{Name: d, Type: t})
		}
	}
	return out
}

// ProbeError explains why a resolver can't be trusted for a run.
type ProbeError struct {
	// Tampered is true when the resolver answered but withheld records that
	// exist, as opposed to being unreachable or failing outright.
	Tampered bool
	// Problems holds one line per failing record type.
	Problems []string
}

func (e *ProbeError) Error() string {
	what := "DNS resolver is not answering correctly"
	if e.Tampered {
		what = "DNS resolver is returning incomplete answers"
	}
	return what + ": " + strings.Join(e.Problems, "; ")
}

// Probe checks that r gives correct answers for well-known public records.
// A resolver that fails would make Seta report existing records as missing,
// so callers should refuse to run with it. Probe returns a *ProbeError when
// the resolver is unreliable, or ctx's error if ctx ends first.
func Probe(ctx context.Context, r Resolver) error {
	type result struct {
		records int
		err     error
	}
	canaries := Canaries()
	results := make([]result, len(canaries))
	var wg sync.WaitGroup
	for i, c := range canaries {
		wg.Go(func() {
			resp, err := r.Lookup(ctx, c.Name, c.Type)
			if err != nil {
				results[i].err = err
				return
			}
			results[i].records = len(resp.Records())
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	pe := &ProbeError{}
	for _, t := range canaryTypes {
		ok, answered := false, false
		var firstErr error
		for i, c := range canaries {
			if c.Type != t {
				continue
			}
			switch r := results[i]; {
			case r.records > 0:
				ok = true
			case r.err == nil:
				answered = true
			case firstErr == nil:
				firstErr = r.err
			}
		}
		typ := dns.TypeToString[t]
		switch {
		case ok:
		case answered:
			pe.Tampered = true
			pe.Problems = append(pe.Problems, fmt.Sprintf("%s lookups for %s returned no records", typ, joinOr(canaryDomains)))
		default:
			pe.Problems = append(pe.Problems, fmt.Sprintf("%s lookups failed (%v)", typ, firstErr))
		}
	}
	if len(pe.Problems) > 0 {
		return pe
	}
	return nil
}

func joinOr(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
