package dnsx

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func TestClientDNSSECFlags(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*dns.Msg
	)
	addr := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		got = append(got, r.Copy())
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})
	c := newTestClient(t, addr)
	if _, err := c.Lookup(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LookupDNSSEC(context.Background(), "example.com", dns.TypeDNSKEY); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got[0].CheckingDisabled || got[0].IsEdns0().Do() {
		t.Error("plain lookup set CD or DO")
	}
	if !got[1].CheckingDisabled || !got[1].IsEdns0().Do() {
		t.Error("DNSSEC lookup did not set CD and DO")
	}
}

func TestFakeAndCacheDNSSEC(t *testing.T) {
	f := NewFake()
	if err := f.AddZoneString("example.com", `
@    SOA  ns hostmaster 1 3600 600 86400 60
@    A    192.0.2.1
@    RRSIG A 13 2 300 20300101000000 20200101000000 1234 example.com. c2ln
www  CNAME @
www  RRSIG CNAME 13 3 300 20300101000000 20200101000000 1234 example.com. c2ln
`); err != nil {
		t.Fatal(err)
	}
	c := NewCache(f)
	plain, err := c.Lookup(context.Background(), "www.example.com", dns.TypeA)
	if err != nil || len(plain.Answer) != 2 || len(plain.RRSIGs()) != 0 {
		t.Errorf("plain lookup = %v, %v", plain, err)
	}
	sec, err := c.LookupDNSSEC(context.Background(), "www.example.com", dns.TypeA)
	if err != nil || len(sec.Answer) != 4 || len(sec.RRSIGs()) != 1 {
		t.Errorf("DNSSEC lookup = %v, %v", sec, err)
	}

	noSec := NewCache(resolverOnly{f})
	if _, err := noSec.LookupDNSSEC(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Error("DNSSEC lookup through a plain resolver succeeded")
	}
}

type resolverOnly struct{ Resolver }
