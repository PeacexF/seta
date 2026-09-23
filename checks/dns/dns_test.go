package dnscheck

import (
	"crypto"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/netx"
	"github.com/PeacexF/seta/internal/registry"
)

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func env(r dnsx.Resolver) checktest.Env {
	return checktest.Env{Resolver: r, Now: func() time.Time { return now }}
}

// signedZone builds a DNSSEC-signed zone for web.test with a KSK and a ZSK.
type signedZone struct {
	t                  *testing.T
	ksk, zsk           *dns.DNSKEY
	kskPriv, zskPriv   crypto.Signer
	soa                *dns.SOA
	inception, expires time.Time
}

func newSignedZone(t *testing.T, alg uint8) *signedZone {
	z := &signedZone{t: t, inception: now.Add(-24 * time.Hour), expires: now.Add(14 * 24 * time.Hour)}
	bits := 256
	if alg == dns.RSASHA1 || alg == dns.RSASHA256 {
		bits = 2048
	}
	z.ksk, z.kskPriv = key(t, alg, 257, bits)
	z.zsk, z.zskPriv = key(t, alg, 256, bits)
	z.soa = &dns.SOA{Hdr: hdr("web.test.", dns.TypeSOA), Ns: "ns.web.test.", Mbox: "h.web.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60}
	return z
}

func hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 300}
}

func key(t *testing.T, alg uint8, flags uint16, bits int) (*dns.DNSKEY, crypto.Signer) {
	k := &dns.DNSKEY{Hdr: hdr("web.test.", dns.TypeDNSKEY), Flags: flags, Protocol: 3, Algorithm: alg}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatal(err)
	}
	return k, priv.(crypto.Signer)
}

func (z *signedZone) sign(k *dns.DNSKEY, priv crypto.Signer, rrs []dns.RR) *dns.RRSIG {
	sig := &dns.RRSIG{Hdr: hdr("web.test.", dns.TypeRRSIG), KeyTag: k.KeyTag(), SignerName: "web.test.", Algorithm: k.Algorithm,
		Inception: uint32(z.inception.Unix()), Expiration: uint32(z.expires.Unix())}
	if err := sig.Sign(priv, rrs); err != nil {
		z.t.Fatal(err)
	}
	return sig
}

// resolver serves the zone; ds is what the parent publishes.
func (z *signedZone) resolver(ds ...*dns.DS) *dnsx.Fake {
	f := dnsx.NewFake()
	keys := []dns.RR{z.ksk, z.zsk}
	f.Add(z.soa, z.ksk, z.zsk, z.sign(z.ksk, z.kskPriv, keys), z.sign(z.zsk, z.zskPriv, []dns.RR{z.soa}))
	for _, d := range ds {
		f.Add(d)
	}
	return f
}

func TestDNSSEC(t *testing.T) {
	z := newSignedZone(t, dns.ECDSAP256SHA256)
	ds := z.ksk.ToDS(dns.SHA256)
	other, _ := key(t, dns.ECDSAP256SHA256, 257, 256)

	expired := newSignedZone(t, dns.ECDSAP256SHA256)
	expired.expires = now.Add(-time.Hour)

	stripped := dnsx.NewFake()
	stripped.Add(z.soa, z.ksk, z.zsk, ds)

	unsigned := dnsx.NewFake()
	unsigned.Add(z.soa)

	rsa := newSignedZone(t, dns.RSASHA1)

	tests := []struct {
		name string
		r    dnsx.Resolver
		want []string
	}{
		{"valid", z.resolver(ds), nil},
		{"unsigned", unsigned, []string{"dns.dnssec.missing=low"}},
		{"signed but not delegated", z.resolver(), []string{"dns.dnssec.missing=low"}},
		{"stale DS after a key rollover", z.resolver(other.ToDS(dns.SHA256)), []string{"dns.dnssec.invalid=critical"}},
		{"expired signatures", expired.resolver(expired.ksk.ToDS(dns.SHA256)), []string{"dns.dnssec.invalid=critical"}},
		{"DS but no keys", func() dnsx.Resolver { f := dnsx.NewFake(); f.Add(z.soa, ds); return f }(), []string{"dns.dnssec.invalid=critical"}},
		{"resolver strips signatures", stripped, []string{"dns.dnssec.invalid!may strip DNSSEC data"}},
		{"RSA/SHA-1 with a SHA-1 DS", rsa.resolver(rsa.ksk.ToDS(dns.SHA1)), []string{"dns.dnssec.weak_algorithm=low"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checktest.Want(t, checktest.Results(t, Checks(), env(tt.r), checktest.Domain(t, "web.test"), "dns.dnssec."), tt.want...)
		})
	}

	// Not a zone apex: DNSSEC is the parent zone's business.
	sub := z.resolver(ds)
	checktest.Want(t, checktest.Results(t, Checks(), env(sub), checktest.Domain(t, "shop.web.test"), "dns.dnssec."))

	fs, _ := checktest.RunWith(t, Check("dns.dnssec.invalid"), env(z.resolver(other.ToDS(dns.SHA256))), checktest.Domain(t, "web.test"))
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence["problem"], "no DNSKEY matches the parent's DS records") {
		t.Errorf("evidence: %+v", fs)
	}
}

func TestCAA(t *testing.T) {
	tests := []struct {
		name, zone, target string
		want               []string
	}{
		{"missing", "@ A 192.0.2.1", "web.test", []string{"dns.caa.missing=low"}},
		{"valid", `@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issuewild ";"
@ CAA 0 iodef "mailto:security@web.test"`, "web.test", nil},
		{"inherited from the parent", `@ CAA 0 issue "pki.goog; cansignhttpexchanges=yes"
shop A 192.0.2.1`, "shop.web.test", nil},
		{"broken", `@ CAA 128 tbs "x"
@ CAA 0 issue "Let's Encrypt"
@ CAA 0 future "ignored"`, "web.test", []string{`dns.caa.invalid[0 issue "Let's Encrypt"]=medium`, `dns.caa.invalid[128 tbs "x"]=medium`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := checktest.Zone(t, "web.test", "$ORIGIN web.test.\n"+tt.zone+"\n")
			checktest.Want(t, checktest.Results(t, Checks(), env(r), checktest.Domain(t, tt.target), "dns.caa."), tt.want...)
		})
	}
}

func TestTakeover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "blog.web.test":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"))
		default:
			w.Write([]byte("<h1>Docs</h1>"))
		}
	}))
	t.Cleanup(srv.Close)
	r := checktest.Zone(t, "web.test", `
$ORIGIN web.test.
@     A     192.0.2.1
www   CNAME old-app.azurewebsites.net.
blog  CNAME acme.github.io.
docs  CNAME acme-docs.github.io.
shop  CNAME shops.example-cdn.net.
api   CNAME api.lb.example-cdn.net.
`)
	if err := r.AddZoneString("github.io", "acme A 192.0.2.10\nacme-docs A 192.0.2.10\n"); err != nil {
		t.Fatal(err)
	}
	if err := r.AddZoneString("example-cdn.net", "api.lb A 192.0.2.20\n"); err != nil {
		t.Fatal(err)
	}
	e := env(r)
	e.Net = netx.Options{DialAddr: checktest.RedirectTo(srv.Listener.Addr().String())}
	tg := checktest.Domain(t, "web.test")
	for _, h := range []string{"blog.web.test", "docs.web.test", "shop.web.test", "api.web.test"} {
		parsed, _ := core.ParseHost(h)
		tg.Hosts = append(tg.Hosts, parsed)
	}
	tg.Hosts = append(tg.Hosts, core.Host{Name: "www.web.test", Port: 443})

	var got []string
	for _, prefix := range []string{"dns.takeover.", "dns.cname."} {
		got = append(got, checktest.Results(t, Checks(), e, tg, prefix)...)
	}
	checktest.Want(t, got,
		"dns.takeover.possible[www.web.test]=high",
		"dns.takeover.possible[blog.web.test]=high",
		"dns.cname.dangling[shop.web.test]=medium",
	)
}

func TestMatchService(t *testing.T) {
	for target, want := range map[string]string{
		"assets.s3.amazonaws.com":                      "AWS S3",
		"assets.s3.eu-west-1.amazonaws.com":            "AWS S3",
		"assets.s3-website-us-east-1.amazonaws.com":    "AWS S3",
		"assets.s3-website.eu-central-1.amazonaws.com": "AWS S3",
		"my-lb-123.eu-west-1.elb.amazonaws.com":        "",
		"ec2-1-2-3-4.compute-1.amazonaws.com":          "",
		"x.trafficmanager.net":                         "Microsoft Azure",
		"notgithub.io.example.com":                     "",
	} {
		got := ""
		if s := matchService(target); s != nil {
			got = s.name
		}
		if got != want {
			t.Errorf("matchService(%q) = %q, want %q", target, got, want)
		}
	}
}

// nameserver is a fake authoritative server on UDP and TCP of one port.
func nameserver(t *testing.T, axfr, recursive bool) string {
	t.Helper()
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeAXFR && axfr:
			soa, _ := dns.NewRR("web.test. 60 IN SOA ns.web.test. h.web.test. 1 3600 600 86400 60")
			a, _ := dns.NewRR("secret-staging.web.test. 60 IN A 10.0.0.5")
			m.Answer = []dns.RR{soa, a, soa}
		case q.Qtype == dns.TypeAXFR:
			m.Rcode = dns.RcodeRefused
		case q.Name == "." && recursive:
			m.RecursionAvailable = true
			ns, _ := dns.NewRR(". 518400 IN NS a.root-servers.net.")
			m.Answer = []dns.RR{ns}
		default:
			m.Rcode = dns.RcodeRefused
		}
		w.WriteMsg(m)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Skipf("no UDP on the TCP port: %v", err)
	}
	for _, s := range []*dns.Server{{Listener: ln, Handler: h}, {PacketConn: pc, Handler: h}} {
		go s.ActivateAndServe()
		t.Cleanup(func() { s.Shutdown() })
	}
	return ln.Addr().String()
}

func TestNameserverProbes(t *testing.T) {
	r := checktest.Zone(t, "web.test", `
$ORIGIN web.test.
@   SOA ns h 1 3600 600 86400 60
@   NS  ns1
@   NS  ns2
ns1 A   192.0.2.53
ns2 A   192.0.2.54
`)
	tests := []struct {
		name            string
		axfr, recursive bool
		want            []string
	}{
		{"locked down", false, false, nil},
		{"transfers and recursion open", true, true, []string{
			"dns.axfr.allowed[ns1.web.test]=high", "dns.axfr.allowed[ns2.web.test]=high",
			"dns.nameserver.open_resolver[ns1.web.test]=medium", "dns.nameserver.open_resolver[ns2.web.test]=medium",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := env(r)
			e.Net = netx.Options{DialAddr: checktest.RedirectTo(nameserver(t, tt.axfr, tt.recursive))}
			var got []string
			for _, prefix := range []string{"dns.axfr.", "dns.nameserver."} {
				got = append(got, checktest.Results(t, Checks(), e, checktest.Domain(t, "web.test"), prefix)...)
			}
			checktest.Want(t, got, tt.want...)
		})
	}
}

func TestMetadataAndRegistration(t *testing.T) {
	for _, c := range Checks() {
		m := c.Meta()
		if m.Description == "" || m.Remediation == "" || len(m.References) == 0 {
			t.Errorf("%s: description, remediation and references are required", m.ID)
		}
		if _, ok := registry.Default.Lookup(m.ID); !ok {
			t.Errorf("%s is not registered", m.ID)
		}
	}
}
