package dnsx

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

const testZone = `
$ORIGIN example.test.
@        IN SOA  ns1 hostmaster 1 3600 600 86400 300
@        IN MX   10 mx1
@        IN MX   20 mx2.other.test.
@        IN TXT  "v=spf1 " "include:_spf.example.test " "-all"
@        IN A    192.0.2.1
mx1      IN A    192.0.2.10
mx1      IN AAAA 2001:db8::10
www      IN CNAME web
web      IN A    192.0.2.20
dangling IN CNAME gone
loop1    IN CNAME loop2
loop2    IN CNAME loop1
a.b.deep IN TXT  "deep"
`

func newTestFake(t *testing.T) *Fake {
	t.Helper()
	f := NewFake()
	if err := f.AddZoneString("example.test", testZone); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFakeAnswers(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		qtype     uint16
		wantRcode int
		wantN     int // records of the queried type
	}{
		{"example.test", dns.TypeMX, dns.RcodeSuccess, 2},
		{"EXAMPLE.test.", dns.TypeMX, dns.RcodeSuccess, 2},  // case-insensitive, FQDN optional
		{"example.test", dns.TypeAAAA, dns.RcodeSuccess, 0}, // NODATA
		{"nope.example.test", dns.TypeA, dns.RcodeNameError, 0},
		{"deep.example.test", dns.TypeTXT, dns.RcodeSuccess, 0}, // empty non-terminal
		{"b.deep.example.test", dns.TypeA, dns.RcodeSuccess, 0},
		{"www.example.test", dns.TypeA, dns.RcodeSuccess, 1}, // via CNAME
		{"www.example.test", dns.TypeCNAME, dns.RcodeSuccess, 1},
		{"dangling.example.test", dns.TypeA, dns.RcodeNameError, 0},
	}
	for _, tt := range tests {
		resp, err := f.Lookup(ctx, tt.name, tt.qtype)
		if err != nil {
			t.Errorf("%s %s: %v", tt.name, dns.TypeToString[tt.qtype], err)
			continue
		}
		if resp.Rcode != tt.wantRcode || len(resp.Records()) != tt.wantN {
			t.Errorf("%s %s: rcode %s, %d records; want %s, %d", tt.name, dns.TypeToString[tt.qtype],
				dns.RcodeToString[resp.Rcode], len(resp.Records()), dns.RcodeToString[tt.wantRcode], tt.wantN)
		}
	}
}

func TestFakeCNAMEChainInAnswer(t *testing.T) {
	f := newTestFake(t)
	resp, err := f.Lookup(context.Background(), "www.example.test", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 2 || resp.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("want CNAME followed by A, got %v", resp.Answer)
	}
	if got := resp.Addrs(); len(got) != 1 || got[0].String() != "192.0.2.20" {
		t.Fatalf("Addrs() = %v", got)
	}
}

func TestFakeCNAMELoopIsAnError(t *testing.T) {
	f := newTestFake(t)
	_, err := f.Lookup(context.Background(), "loop1.example.test", dns.TypeA)
	var dnsErr *Error
	if !errors.As(err, &dnsErr) || dnsErr.Rcode != dns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL error for CNAME loop, got %v", err)
	}
}

func TestResponseHelpers(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()

	txt, _ := f.Lookup(ctx, "example.test", dns.TypeTXT)
	if got := txt.TXT(); !slices.Equal(got, []string{"v=spf1 include:_spf.example.test -all"}) {
		t.Errorf("TXT strings not concatenated: %q", got)
	}

	mx, _ := f.Lookup(ctx, "example.test", dns.TypeMX)
	var hosts []string
	for _, m := range mx.MX() {
		hosts = append(hosts, m.Mx)
	}
	slices.Sort(hosts)
	if !slices.Equal(hosts, []string{"mx1.example.test.", "mx2.other.test."}) {
		t.Errorf("MX hosts = %v", hosts)
	}

	a, _ := f.Lookup(ctx, "mx1.example.test", dns.TypeAAAA)
	if got := a.Addrs(); len(got) != 1 || got[0].String() != "2001:db8::10" {
		t.Errorf("AAAA addrs = %v", got)
	}
}

func TestFakeSetError(t *testing.T) {
	f := newTestFake(t)
	f.SetError("example.test", dns.TypeMX, nil)
	_, err := f.Lookup(context.Background(), "example.test", dns.TypeMX)
	if err == nil || err.Error() != "lookup MX example.test: server responded SERVFAIL" {
		t.Fatalf("got %v", err)
	}
	// Other types for the same name are unaffected.
	if _, err := f.Lookup(context.Background(), "example.test", dns.TypeTXT); err != nil {
		t.Fatalf("TXT lookup failed: %v", err)
	}
}

func TestFakeHonorsContext(t *testing.T) {
	f := newTestFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Lookup(ctx, "example.test", dns.TypeMX); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestLoadFakeDir(t *testing.T) {
	f, err := LoadFakeDir("../../testdata/zones")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.Lookup(context.Background(), "mx-ok.test", dns.TypeMX)
	if err != nil || len(resp.MX()) == 0 {
		t.Fatalf("fixture zone mx-ok.test not loaded: %v %v", resp, err)
	}
	if _, err := LoadFakeDir(t.TempDir()); err == nil {
		t.Error("empty fixture dir should be an error")
	}
}

func TestAddZoneReportsSyntaxErrors(t *testing.T) {
	err := NewFake().AddZoneString("bad.test", "@ IN MX notanumber mx\n")
	if err == nil {
		t.Fatal("expected a parse error")
	}
}
