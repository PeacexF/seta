package dnsx

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Fake is an in-memory Resolver for tests. It answers from records loaded out
// of RFC 1035 zone files and behaves like a recursive resolver: CNAMEs are
// followed, names with no records of the queried type get NOERROR/NODATA,
// and unknown names get NXDOMAIN. Wildcards are not supported.
type Fake struct {
	mu      sync.RWMutex
	records map[string][]dns.RR // owner name -> records
	exists  map[string]bool     // owner names and their ancestors (empty non-terminals)
	errs    map[cacheKey]error
}

// NewFake returns an empty fake resolver.
func NewFake() *Fake {
	return &Fake{
		records: make(map[string][]dns.RR),
		exists:  make(map[string]bool),
		errs:    make(map[cacheKey]error),
	}
}

// LoadFakeDir returns a fake loaded with every "*.zone" file in dir. Each
// file's origin is its base name without the extension, so
// "example.com.zone" holds the example.com zone.
func LoadFakeDir(dir string) (*Fake, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.zone"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no *.zone files in %s", dir)
	}
	f := NewFake()
	for _, p := range paths {
		if err := f.AddZoneFile(p); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// AddZoneFile loads a zone file whose origin is its base name without ".zone".
func (f *Fake) AddZoneFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	origin := strings.TrimSuffix(filepath.Base(path), ".zone")
	return f.AddZone(file, origin, path)
}

// AddZoneString loads zone text with the given origin. Handy for inline
// fixtures in table-driven tests.
func (f *Fake) AddZoneString(origin, zone string) error {
	return f.AddZone(strings.NewReader(zone), origin, "inline:"+origin)
}

// AddZone loads zone text from r. filename is used only in error messages.
func (f *Fake) AddZone(r io.Reader, origin, filename string) error {
	zp := dns.NewZoneParser(r, dns.Fqdn(origin), filename)
	zp.SetDefaultTTL(300)
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return err
	}
	f.Add(rrs...)
	return nil
}

// Add inserts records.
func (f *Fake) Add(rrs ...dns.RR) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rr := range rrs {
		name := CanonicalName(rr.Header().Name)
		rr.Header().Name = name
		f.records[name] = append(f.records[name], rr)
		for n := name; ; {
			f.exists[n] = true
			i, end := dns.NextLabel(n, 0)
			if end {
				break
			}
			n = n[i:]
		}
	}
}

// AddCanaries inserts stand-in answers for every query Probe makes, so a fake
// passes the resolver check.
func (f *Fake) AddCanaries() {
	for _, c := range Canaries() {
		f.Add(canaryRR(c))
	}
}

func canaryRR(c Canary) dns.RR {
	hdr := dns.RR_Header{Name: dns.Fqdn(c.Name), Rrtype: c.Type, Class: dns.ClassINET, Ttl: 300}
	switch c.Type {
	case dns.TypeA:
		return &dns.A{Hdr: hdr, A: []byte{192, 0, 2, 1}}
	case dns.TypeMX:
		return &dns.MX{Hdr: hdr, Preference: 10, Mx: "mx." + dns.Fqdn(c.Name)}
	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: []string{"v=spf1 -all"}}
	}
	panic("dnsx: no fake record for canary type " + dns.TypeToString[c.Type])
}

// SetError makes queries for name and qtype fail with err. A nil err
// simulates SERVFAIL.
func (f *Fake) SetError(name string, qtype uint16, err error) {
	name = CanonicalName(name)
	if err == nil {
		err = &Error{Name: name, Type: qtype, Rcode: dns.RcodeServerFailure}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[cacheKey{name, qtype}] = err
}

// maxCNAMEChain bounds CNAME following, like a real resolver would.
const maxCNAMEChain = 8

func (f *Fake) Lookup(ctx context.Context, name string, qtype uint16) (*Response, error) {
	name = CanonicalName(name)
	if err := ctx.Err(); err != nil {
		return nil, &Error{Name: name, Type: qtype, Err: err}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	resp := &Response{Name: name, Type: qtype, Rcode: dns.RcodeSuccess}
	current := name
	for range maxCNAMEChain {
		if err, ok := f.errs[cacheKey{current, qtype}]; ok {
			return nil, err
		}
		var cname *dns.CNAME
		matched := false
		for _, rr := range f.records[current] {
			switch {
			case rr.Header().Rrtype == qtype:
				resp.Answer = append(resp.Answer, rr)
				matched = true
			case rr.Header().Rrtype == dns.TypeCNAME:
				cname = rr.(*dns.CNAME)
			}
		}
		if matched || cname == nil || qtype == dns.TypeCNAME {
			if !f.exists[current] {
				resp.Rcode = dns.RcodeNameError
			}
			return resp, nil
		}
		resp.Answer = append(resp.Answer, cname)
		current = CanonicalName(cname.Target)
	}
	return nil, &Error{Name: name, Type: qtype, Rcode: dns.RcodeServerFailure}
}
