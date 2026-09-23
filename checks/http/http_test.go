package httpcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/netx"
	"github.com/PeacexF/seta/internal/registry"
)

const zone = `
$ORIGIN web.test.
@      A 192.0.2.1
www    A 192.0.2.1
`

// site answers per host name; plain handles port 80, secure port 443.
type site struct {
	plain, secure map[string]http.HandlerFunc
	// plainDown makes port 80 time out.
	plainDown bool
}

func (s site) env(t *testing.T, zoneText string) checktest.Env {
	t.Helper()
	route := func(hs map[string]http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := strings.Cut(r.Host, ":")
			if h := hs[host]; h != nil {
				h(w, r)
				return
			}
			http.NotFound(w, r)
		})
	}
	plain := httptest.NewServer(route(s.plain))
	secure := httptest.NewTLSServer(route(s.secure))
	t.Cleanup(plain.Close)
	t.Cleanup(secure.Close)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		if strings.HasSuffix(addr, ":80") {
			if s.plainDown {
				return nil, errors.New("i/o timeout")
			}
			return d.DialContext(ctx, network, plain.Listener.Addr().String())
		}
		return d.DialContext(ctx, network, secure.Listener.Addr().String())
	}
	return checktest.Env{
		Resolver: checktest.Zone(t, "web.test", zoneText),
		Net:      netx.Options{DialAddr: dial},
		Now:      func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func redirect(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, to, http.StatusMovedPermanently) }
}

func htmlPage(headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Write([]byte("<!doctype html><title>home</title>"))
	}
}

var good = map[string]string{
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
	"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'",
	"X-Content-Type-Options":    "nosniff",
	"Referrer-Policy":           "no-referrer",
}

func withHSTS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", good["Strict-Transport-Security"])
		h(w, r)
	}
}

func passive(t *testing.T, e checktest.Env, tg core.Target) []string {
	t.Helper()
	var out []string
	for _, c := range Checks() {
		if c.Meta().Mode == core.Passive {
			out = append(out, checktest.Results(t, Checks(), e, tg, c.Meta().ID)...)
		}
	}
	return out
}

func TestPassiveChecks(t *testing.T) {
	tg := checktest.Domain(t, "web.test")
	tests := []struct {
		name string
		site site
		zone string
		want []string
	}{
		{"healthy", site{
			plain:  map[string]http.HandlerFunc{"web.test": redirect("https://web.test/"), "www.web.test": redirect("https://www.web.test/")},
			secure: map[string]http.HandlerFunc{"web.test": htmlPage(good), "www.web.test": withHSTS(redirect("https://web.test/"))},
		}, zone, nil},
		{"bare site", site{
			plain:  map[string]http.HandlerFunc{"web.test": htmlPage(nil)},
			secure: map[string]http.HandlerFunc{"web.test": htmlPage(nil)},
		}, "$ORIGIN web.test.\n@ A 192.0.2.1\n", []string{
			"http.redirect.missing[web.test]=medium", "http.hsts.missing[web.test]=medium",
			"http.headers.csp_missing[web.test]=low", "http.headers.frame_protection_missing[web.test]=low",
			"http.headers.nosniff_missing[web.test]=low", "http.headers.referrer_policy_missing[web.test]=info",
		}},
		{"weak HSTS asking for preload, XFO instead of frame-ancestors", site{
			plain: map[string]http.HandlerFunc{"web.test": redirect("https://www.web.test/")},
			secure: map[string]http.HandlerFunc{"web.test": htmlPage(map[string]string{
				"Strict-Transport-Security": "max-age=300; preload", "Content-Security-Policy": "default-src 'self'",
				"X-Frame-Options": "sameorigin", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
			})},
		}, "$ORIGIN web.test.\n@ A 192.0.2.1\n", []string{"http.hsts.weak[web.test]=low", "http.hsts.preload_not_ready[web.test]=low"}},
		{"HSTS only on the first, same-host redirect", site{
			plain: map[string]http.HandlerFunc{"web.test": redirect("https://web.test/")},
			secure: map[string]http.HandlerFunc{"web.test": func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					withHSTS(redirect("/home"))(w, r)
					return
				}
				htmlPage(map[string]string{"Content-Security-Policy": "frame-ancestors 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})(w, r)
			}},
		}, "$ORIGIN web.test.\n@ A 192.0.2.1\n", nil},
		{"apex redirects to www without HSTS", site{
			plain:  map[string]http.HandlerFunc{"web.test": redirect("https://www.web.test/"), "www.web.test": redirect("https://www.web.test/")},
			secure: map[string]http.HandlerFunc{"web.test": redirect("https://www.web.test/"), "www.web.test": htmlPage(good)},
		}, zone, nil},
		{"port 80 firewalled, www redirects off-site", site{
			plainDown: true,
			secure: map[string]http.HandlerFunc{"web.test": htmlPage(good),
				"www.web.test": withHSTS(redirect("https://login.elsewhere.test/"))},
		}, zone, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checktest.Want(t, passive(t, tt.site.env(t, tt.zone), tg), tt.want...)
		})
	}
}

func TestExplicitURLs(t *testing.T) {
	s := site{secure: map[string]http.HandlerFunc{"web.test": func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app":
			htmlPage(good)(w, r)
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}}}
	tg := checktest.Domain(t, "web.test")
	tg.URLs = []string{"https://web.test/app", "https://web.test/api"}
	e := s.env(t, zone)
	var got []string
	for _, id := range []string{"http.headers.csp_missing", "http.headers.nosniff_missing"} {
		got = append(got, checktest.Results(t, Checks(), e, tg, id)...)
	}
	// The JSON API needs nosniff but no CSP.
	checktest.Want(t, got, "http.headers.nosniff_missing[web.test/api]=low")

	tg.URLs = []string{"https://web.test/missing"}
	checktest.Want(t, checktest.Results(t, Checks(), e, tg, "http.headers.csp_missing"), "http.headers.csp_missing!HTTP 404")
}

func TestSensitivePaths(t *testing.T) {
	files := map[string]struct{ contentType, body string }{
		"/.git/HEAD": {"application/octet-stream", "ref: refs/heads/main\n"},
		"/.env":      {"text/plain", "# prod\nDB_PASSWORD=hunter2\nexport API_KEY=abc\n"},
	}
	exposed := func(w http.ResponseWriter, r *http.Request) {
		if f, ok := files[r.URL.Path]; ok {
			w.Header().Set("Content-Type", f.contentType)
			w.Write([]byte(f.body))
			return
		}
		htmlPage(nil)(w, r)
	}
	// Answers every path with 200 text: must not count.
	catchAll := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Welcome to our site!\nPlease log in."))
	}
	s := site{secure: map[string]http.HandlerFunc{"web.test": exposed, "www.web.test": catchAll}}
	e := s.env(t, zone)
	tg := checktest.Domain(t, "web.test")
	checktest.Want(t, checktest.Results(t, Checks(), e, tg, "http.exposure."),
		"http.exposure.sensitive_path[web.test/.env]=critical", "http.exposure.sensitive_path[web.test/.git/HEAD]=high")

	fs, _ := checktest.RunWith(t, Check("http.exposure.sensitive_path"), e, tg)
	for _, f := range fs {
		for _, v := range f.Evidence {
			if strings.Contains(v, "hunter2") || strings.Contains(v, "abc") {
				t.Errorf("evidence leaks a secret: %v", f.Evidence)
			}
		}
		if f.Subject == "web.test/.env" && f.Evidence["variables"] != "DB_PASSWORD, API_KEY" {
			t.Errorf(".env evidence = %v", f.Evidence)
		}
	}
}

func TestParseHSTS(t *testing.T) {
	for in, want := range map[string]hsts{
		`max-age=31536000; includeSubDomains; preload`: {maxAge: 31536000, includeSubDomains: true, preload: true},
		`MAX-AGE="600"`:                   {maxAge: 600},
		`includeSubDomains`:               {maxAge: -1, includeSubDomains: true, invalid: "no max-age directive"},
		`max-age=1; max-age=2`:            {maxAge: 2, invalid: "directive max-age appears more than once"},
		`max-age=-5`:                      {maxAge: -1, invalid: `invalid max-age "-5"`},
		`max-age=10;;  preload ; foo=bar`: {maxAge: 10, preload: true},
	} {
		got := parseHSTS(in)
		got.raw = ""
		if got != want {
			t.Errorf("parseHSTS(%q) = %+v, want %+v", in, got, want)
		}
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
