package plugin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
)

// TestExamples loads the example plugins through the real protocol. Their
// checks need the network, so a run passes as long as it ends in findings
// or an error the plugin reported itself, never a protocol failure.
func TestExamples(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the example plugins")
	}
	dir := t.TempDir()
	examples := filepath.Join("..", "..", "examples", "plugins")
	want := map[string]string{}

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not in PATH")
	}
	out := filepath.Join(dir, Prefix+"securitytxt")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	if b, err := exec.Command(goTool, "build", "-o", out, "./"+filepath.ToSlash(filepath.Join(examples, "securitytxt"))).CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	want["securitytxt"] = "securitytxt.file.missing securitytxt.file.expired"

	scripts := map[string][]string{"ipv6": {"python3"}, "robotstxt": {"bash", "curl", "jq"}}
	for name, needs := range scripts {
		if runtime.GOOS == "windows" {
			break // runs scripts only through PATHEXT associations
		}
		missing := ""
		for _, n := range needs {
			if _, err := exec.LookPath(n); err != nil {
				missing = n
			}
		}
		if missing != "" {
			t.Logf("skipping %s: %s not in PATH", name, missing)
			continue
		}
		data, err := os.ReadFile(filepath.Join(examples, name, Prefix+name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, Prefix+name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		want[name] = map[string]string{"ipv6": "ipv6.host.missing", "robotstxt": "robotstxt.site.disallow_all"}[name]
	}

	ps, es := load(t, Options{Dirs: []string{dir}})
	if len(es) > 0 {
		t.Fatalf("load errors: %v", es)
	}
	target := checktest.Domain(t, "nonexistent.invalid")
	for name, ids := range want {
		p := ps[name]
		if p == nil || p.Version != "0.1.0" {
			t.Errorf("%s not loaded: %+v", name, p)
			continue
		}
		var got []string
		for _, c := range p.Checks {
			got = append(got, c.Meta().ID)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_, err := c.Run(ctx, core.Env{}, target)
			cancel()
			if err != nil && !strings.HasPrefix(err.Error(), "plugin: ") {
				t.Errorf("%s: %v", c.Meta().ID, err)
			}
		}
		if strings.Join(got, " ") != ids {
			t.Errorf("%s checks = %v, want %s", name, got, ids)
		}
	}
}
