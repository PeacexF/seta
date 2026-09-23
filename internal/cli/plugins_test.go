package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/sdk"
)

// The test binary doubles as plugins, see checktest.InstallSelf.
func TestMain(m *testing.M) {
	if name, ok := checktest.PluginName(); ok {
		os.Exit(fakePlugin(name).Serve(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func fakePlugin(name string) *sdk.Plugin {
	return &sdk.Plugin{Name: name, Version: "0.1.0", Checks: []sdk.Check{
		{
			CheckInfo: sdk.CheckInfo{ID: name + ".config.echo", Title: "Echoes its config", Mode: sdk.Passive, Severity: sdk.Medium,
				Description: "Reports its config.", Remediation: "Nothing to fix."},
			Run: func(_ context.Context, req *sdk.Request) ([]sdk.Finding, error) {
				var cfg struct{ Subject string }
				if err := req.DecodeConfig(&cfg); err != nil {
					return nil, err
				}
				return []sdk.Finding{{Subject: cfg.Subject, Evidence: map[string]string{"config": string(req.Config)}}}, nil
			},
		},
		{
			CheckInfo: sdk.CheckInfo{ID: name + ".probe.active", Title: "Connects", Mode: sdk.Active, Severity: sdk.High},
			Run:       func(context.Context, *sdk.Request) ([]sdk.Finding, error) { return nil, nil },
		},
	}}
}

func TestPluginsList(t *testing.T) {
	dir := t.TempDir()
	checktest.InstallSelf(t, dir, "demo", "email")
	h := &harness{path: dir}
	exe := filepath.Join(dir, "seta-plugin-demo")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	code, out, _ := h.run(t, "plugins", "list")
	if code != ExitOK || !strings.Contains(out, "demo  0.1.0    2       "+exe+"\n") ||
		!strings.Contains(out, "\nProblems:\n") || !strings.Contains(out, `"email" is the name of a built-in module`) {
		t.Errorf("code %d:\n%s", code, out)
	}

	if code, out, _ := (&harness{}).run(t, "plugins", "list"); code != ExitOK || !strings.Contains(out, "No plugins found") {
		t.Errorf("none: code %d:\n%s", code, out)
	}
	if code, _, errOut := h.run(t, "--no-plugins", "plugins", "list"); code != ExitUsage || !strings.Contains(errOut, "disabled by --no-plugins") {
		t.Errorf("--no-plugins: code %d: %s", code, errOut)
	}
}

func TestPluginChecksInConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	checktest.InstallSelf(t, filepath.Join(dir, "plugins"), "demo")
	path := filepath.Join(dir, "seta.yaml")
	src := `version: 1
plugins_dir: plugins
plugins:
  demo: {subject: global}
defaults:
  checks: ["demo.*"]
targets:
  - domain: mx-ok.test
    plugins:
      demo: {subject: own}
  - domain: mx-none.test
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := (&harness{}).run(t, "run", "-c", path, "-f", "json", "--fail-on", "none")
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errOut)
	}
	for _, want := range []string{`"subject": "own"`, `"subject": "global"`, `"config": "{\"subject\":\"own\"}"`, `"check_id": "demo.config.echo"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "demo.probe.active") {
		t.Error("active plugin check ran without --active")
	}

	code, out, _ = (&harness{}).run(t, "checks", "list", "-c", path)
	if code != ExitOK || !strings.Contains(out, "demo.config.echo") || !strings.Contains(out, "demo.probe.active  active") {
		t.Errorf("checks list: code %d:\n%s", code, out)
	}
	code, out, _ = (&harness{}).run(t, "checks", "explain", "-c", path, "demo.config.echo")
	if code != ExitOK || !strings.Contains(out, "Reports its config.") {
		t.Errorf("checks explain: code %d:\n%s", code, out)
	}

	code, _, errOut = (&harness{}).run(t, "--no-plugins", "run", "-c", path)
	if code != ExitUsage || !strings.Contains(errOut, `no plugin named "demo" is installed`) {
		t.Errorf("--no-plugins: code %d: %s", code, errOut)
	}
}

func TestScanRunsPathPlugins(t *testing.T) {
	dir := t.TempDir()
	checktest.InstallSelf(t, dir, "demo", "ct")
	code, out, errOut := (&harness{path: dir}).run(t, "scan", "--only", "demo.*", "mx-ok.test")
	if code != ExitOK || !strings.Contains(out, "demo.config.echo") || !strings.Contains(out, "config: {}") {
		t.Errorf("code %d:\n%s", code, out)
	}
	if !strings.Contains(errOut, `warning: plugin ct (`) || !strings.Contains(errOut, "its checks are unavailable") {
		t.Errorf("no warning about the unusable plugin: %s", errOut)
	}
}
