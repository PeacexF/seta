package dnsx

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// canaryFake answers every canary query except those skip rejects.
func canaryFake(t *testing.T, skip func(c Canary) bool) *Fake {
	t.Helper()
	f := NewFake()
	for _, c := range Canaries() {
		if skip == nil || !skip(c) {
			f.Add(canaryRR(c))
		}
	}
	return f
}

func TestProbeHonestResolver(t *testing.T) {
	if err := Probe(context.Background(), canaryFake(t, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestProbeToleratesOneCanaryChanging(t *testing.T) {
	f := canaryFake(t, func(c Canary) bool { return c.Name == "yahoo.com" })
	f.SetError("outlook.com", dns.TypeTXT, nil)
	if err := Probe(context.Background(), f); err != nil {
		t.Fatal(err)
	}
}

func TestProbeDetectsTampering(t *testing.T) {
	// Like the networks that answer A honestly and blank everything else.
	f := canaryFake(t, func(c Canary) bool { return c.Type != dns.TypeA })
	err := Probe(context.Background(), f)
	var pe *ProbeError
	if !errors.As(err, &pe) || !pe.Tampered || len(pe.Problems) != 3 {
		t.Fatalf("want tampering with 3 problems, got %#v", err)
	}
	for _, want := range []string{"MX lookups for gmail.com, outlook.com and yahoo.com returned no records", "TXT lookups",
		"DS lookups for cloudflare.com, ietf.org and isc.org returned no records"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestProbeDetectsUnreachableResolver(t *testing.T) {
	f := NewFake()
	for _, c := range Canaries() {
		f.SetError(c.Name, c.Type, &Error{Name: c.Name, Type: c.Type, Err: errors.New("i/o timeout")})
	}
	err := Probe(context.Background(), f)
	var pe *ProbeError
	if !errors.As(err, &pe) || pe.Tampered || len(pe.Problems) != 4 {
		t.Fatalf("want 4 unreachable problems, got %#v", err)
	}
	if !strings.Contains(err.Error(), "i/o timeout") {
		t.Errorf("error should carry the cause: %v", err)
	}
}

func TestProbeHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Probe(ctx, canaryFake(t, nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
