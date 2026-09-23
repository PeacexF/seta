package netx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/PeacexF/seta/internal/dnsx"
)

func testResolver(t *testing.T) *dnsx.Fake {
	f := dnsx.NewFake()
	if err := f.AddZoneString("net.test", `
$ORIGIN net.test.
dual  A    192.0.2.1
dual  AAAA 2001:db8::1
v6    AAAA 2001:db8::2
none  TXT  "no addresses"
`); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLookupAddrs(t *testing.T) {
	n := New(testResolver(t), Options{})
	ctx := context.Background()
	got, err := n.LookupAddrs(ctx, "dual.net.test")
	if err != nil || len(got) != 2 || !got[0].Is4() {
		t.Errorf("dual: %v %v (IPv4 must come first)", got, err)
	}
	if got, err := n.LookupAddrs(ctx, "192.0.2.9"); err != nil || got[0].String() != "192.0.2.9" {
		t.Errorf("IP literal: %v %v", got, err)
	}
	for _, name := range []string{"none.net.test", "missing.net.test"} {
		if _, err := n.LookupAddrs(ctx, name); !errors.Is(err, ErrNoAddress) {
			t.Errorf("%s: want ErrNoAddress, got %v", name, err)
		}
	}
}

func TestDialTriesEachAddress(t *testing.T) {
	var tried []string
	n := New(testResolver(t), Options{DialAddr: func(_ context.Context, _, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		if addr == "[2001:db8::1]:25" {
			c, _ := net.Pipe()
			return c, nil
		}
		return nil, errors.New("unreachable")
	}})
	conn, err := n.Dial(context.Background(), "tcp", "dual.net.test:25")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !slices.Equal(tried, []string{"192.0.2.1:25", "[2001:db8::1]:25"}) {
		t.Errorf("dial order = %v", tried)
	}
}

func TestHTTPClient(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	f := testResolver(t)
	n := New(f, Options{UserAgent: "seta/test", DialAddr: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}})
	resp, err := n.HTTPClient().Get("http://dual.net.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("redirect was followed: status %d", resp.StatusCode)
	}
	if ua != "seta/test" {
		t.Errorf("User-Agent = %q", ua)
	}
}
