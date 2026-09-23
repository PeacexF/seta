package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/PeacexF/seta/checks/email"
	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/notify"
)

// hook collects webhook deliveries and replies with status.
type hook struct {
	payloads chan map[string]any
	status   int
}

func newHook(t *testing.T, status int) (*hook, string) {
	h := &hook{payloads: make(chan map[string]any, 10), status: status}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Seta-Signature-256") != notify.Sign("s3cret", body) {
			t.Error("bad signature")
		}
		var p map[string]any
		json.Unmarshal(body, &p)
		h.payloads <- p
		w.WriteHeader(h.status)
	}))
	t.Cleanup(srv.Close)
	return h, srv.URL
}

func daemonConfig(t *testing.T, hookURL string) (dir, path string) {
	dir = t.TempDir()
	path = filepath.Join(dir, "seta.yaml")
	cfg := mxConfig + "schedule: \"0 0 1 1 *\"\nstate:\n  path: " + filepath.Join(dir, "state.db") +
		"\nnotify:\n  - type: webhook\n    url: " + hookURL + "\n    secret: s3cret\n"
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

// runDaemon starts the daemon, lets it finish its start-up run, and stops it.
func runDaemon(t *testing.T, h *harness, wait func(), args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result)
	go func() {
		code, _, stderr := h.runCtx(t, ctx, append([]string{"daemon"}, args...)...)
		done <- result{code, stderr}
	}()
	wait()
	cancel()
	select {
	case r := <-done:
		return r.code, r.stderr
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
		return 0, ""
	}
}

func TestDaemon(t *testing.T) {
	hk, url := newHook(t, 200)
	dir, path := daemonConfig(t, url)
	var first map[string]any
	code, stderr := runDaemon(t, mxHarness(), func() { first = <-hk.payloads }, "-c", path)
	if code != ExitOK {
		t.Fatalf("code %d, stderr:\n%s", code, stderr)
	}
	changes := first["changes"].([]any)
	if first["event"] != "digest" || len(changes) != 2 || changes[0].(map[string]any)["kind"] != "new" {
		t.Errorf("first digest: %v", first)
	}
	for _, want := range []string{"seta daemon started", "run finished", "new=2", "seta daemon stopped"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("log missing %q:\n%s", want, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "state.db")); err != nil {
		t.Fatal(err)
	}

	// A restart finds the same problems: nothing to report.
	logged := make(chan struct{})
	h := mxHarness()
	h.onStderr = func(s string) {
		if strings.Contains(s, "run finished") {
			close(logged)
			h.onStderr = nil
		}
	}
	code, stderr = runDaemon(t, h, func() { <-logged }, "-c", path, "--log-format", "json")
	if code != ExitOK || !strings.Contains(stderr, `"msg":"run finished"`) || !strings.Contains(stderr, `"new":0`) {
		t.Fatalf("restart: code %d\n%s", code, stderr)
	}
	select {
	case p := <-hk.payloads:
		t.Errorf("unexpected notification after restart: %v", p)
	default:
	}
}

func TestDaemonHealth(t *testing.T) {
	hk, url := newHook(t, 200)
	_, path := daemonConfig(t, url)
	healthURL := make(chan string, 1)
	h := mxHarness()
	h.onStderr = func(s string) {
		if _, u, ok := strings.Cut(s, "url="); ok && strings.Contains(s, "serving health checks") {
			healthURL <- strings.TrimSpace(u)
		}
	}
	var health map[string]any
	code, stderr := runDaemon(t, h, func() {
		u := <-healthURL
		<-hk.payloads
		for range 50 {
			resp, err := http.Get(u)
			if err == nil {
				json.NewDecoder(resp.Body).Decode(&health)
				resp.Body.Close()
				if health["status"] == "ok" {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}, "-c", path, "--listen", "127.0.0.1:0")
	if code != ExitOK || health["status"] != "ok" || health["last_run"].(map[string]any)["new"] != float64(2) {
		t.Errorf("code %d, health %v\n%s", code, health, stderr)
	}
}

func TestNotifyTest(t *testing.T) {
	hk, url := newHook(t, 200)
	_, path := daemonConfig(t, url)
	code, out, errOut := mxHarness().run(t, "notify", "test", "-c", path)
	if code != ExitOK || out != "✓ webhook\n" {
		t.Fatalf("code %d, %q, %s", code, out, errOut)
	}
	if p := <-hk.payloads; p["event"] != "test" {
		t.Errorf("payload %v", p)
	}

	bad, badURL := newHook(t, 403)
	_, path = daemonConfig(t, badURL)
	code, out, errOut = mxHarness().run(t, "notify", "test", "-c", path)
	<-bad.payloads
	if code != ExitFindings || !strings.HasPrefix(out, "✗ webhook: HTTP 403") || !strings.Contains(errOut, "1 notifier failed") {
		t.Errorf("code %d, %q, %s", code, out, errOut)
	}
	if code, _, errOut := mxHarness().run(t, "notify", "test", "-c", path, "--name", "nope"); code != ExitUsage || !strings.Contains(errOut, `no notifier named "nope"`) {
		t.Errorf("--name nope: code %d, %s", code, errOut)
	}
}

// TestDaemonChangeAndRevert is the v0.3 exit criterion in miniature: breaking
// a record sends exactly one "new" alert, and fixing it exactly one
// "resolved" alert once it has been gone for resolve_after runs.
func TestDaemonChangeAndRevert(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the daemon for several seconds")
	}
	hk, url := newHook(t, 200)
	dir := t.TempDir()
	path := filepath.Join(dir, "seta.yaml")
	os.WriteFile(path, []byte("version: 1\ntargets:\n  - domain: mx-ok.test\n    checks: [email.mx.missing]\n"+
		"schedule: \"@every 1s\"\nstate:\n  path: "+filepath.Join(dir, "state.db")+
		"\nnotify:\n  - type: webhook\n    url: "+url+"\n    secret: s3cret\n"), 0o644)

	var broken atomic.Bool
	honest := checktest.Fixtures(t)
	h := &harness{checks: email.Checks(), system: resolverFunc(func(ctx context.Context, name string, qtype uint16) (*dnsx.Response, error) {
		if broken.Load() && dnsx.CanonicalName(name) == "mx-ok.test." && qtype == dns.TypeMX {
			return &dnsx.Response{Name: "mx-ok.test.", Type: qtype}, nil
		}
		return honest.Lookup(ctx, name, qtype)
	})}
	runs := make(chan int, 20)
	n := 0
	h.onStderr = func(s string) {
		if strings.Contains(s, "run finished") {
			n++
			runs <- n
		}
	}

	var kinds []string
	_, stderr := runDaemon(t, h, func() {
		for n := range runs {
			switch n {
			case 1:
				broken.Store(true) // someone deletes the MX records
			case 2:
				broken.Store(false) // and puts them back
			case 6:
				return
			}
		}
	}, "-c", path)
	close(hk.payloads)
	for p := range hk.payloads {
		for _, c := range p["changes"].([]any) {
			c := c.(map[string]any)
			kinds = append(kinds, fmt.Sprintf("run %v: %s %s", p["run"].(map[string]any)["id"], c["kind"], c["check_id"]))
		}
	}
	want := []string{"run 2: new email.mx.missing", "run 4: resolved email.mx.missing"}
	if !slices.Equal(kinds, want) {
		t.Errorf("notifications:\n%s\nwant:\n%s\nlog:\n%s", strings.Join(kinds, "\n"), strings.Join(want, "\n"), stderr)
	}
}
