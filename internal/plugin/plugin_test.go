package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/sdk"
)

// The test binary doubles as every fake plugin: linked as seta-plugin-<name>,
// it behaves as fakePlugin(name).
func TestMain(m *testing.M) {
	if name, ok := checktest.PluginName(); ok {
		os.Exit(fakePlugin(name, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakePlugin(name string, args []string) int {
	out := json.NewEncoder(os.Stdout)
	if args[0] == "describe" {
		d := sdk.Describe{Protocol: sdk.Protocol, Name: name, Version: "1.2.3"}
		for _, c := range []string{"ok", "finding", "fail", "junk", "crash", "slow", "env", "badsev", "two"} {
			d.Checks = append(d.Checks, sdk.CheckInfo{ID: name + ".x." + c, Title: "Check " + c, Mode: sdk.Passive, Severity: sdk.Medium})
		}
		switch name {
		case "proto2":
			d.Protocol = 2
		case "liar":
			d.Name = "other"
		case "foreign":
			d.Checks[0].ID = "other.x.y"
		case "hang":
			time.Sleep(time.Minute)
		case "active":
			d.Checks = []sdk.CheckInfo{{ID: "active.x.y", Title: "t", Mode: sdk.Active, Severity: sdk.High, Timeout: "3s"}}
		}
		out.Encode(d)
		return 0
	}

	var req sdk.Request
	json.NewDecoder(os.Stdin).Decode(&req)
	fmt.Fprintln(os.Stderr, "starting", req.Check)
	resp := sdk.Response{Findings: []sdk.Finding{}}
	_, c, _ := strings.Cut(strings.TrimPrefix(req.Check, name+"."), ".")
	switch c {
	case "finding":
		var cfg struct{ Subject string }
		json.Unmarshal(req.Config, &cfg)
		resp.Findings = []sdk.Finding{{Subject: cfg.Subject, Severity: sdk.High,
			Evidence: map[string]string{"target": req.Target.Name, "deadline": fmt.Sprint(!req.Deadline.IsZero())}}}
	case "fail":
		msg := "lookup failed"
		resp.Error = &msg
	case "junk":
		fmt.Println("not json")
		return 0
	case "crash":
		fmt.Fprintln(os.Stderr, "boom")
		return 3
	case "slow":
		time.Sleep(time.Minute)
	case "env":
		_, leaked := os.LookupEnv("SETA_TG_TOKEN")
		resp.Findings = []sdk.Finding{{Evidence: map[string]string{
			"leaked": fmt.Sprint(leaked), "protocol": os.Getenv(sdk.EnvProtocol), "version": os.Getenv(sdk.EnvVersion)}}}
	case "badsev":
		resp.Findings = []sdk.Finding{{Severity: "severe"}}
	case "two":
		out.Encode(resp)
	}
	out.Encode(resp)
	return 0
}

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		if v, ok := vars[k]; ok {
			return v, true
		}
		return os.LookupEnv(k)
	}
}

func load(t *testing.T, opts Options) (map[string]*Plugin, map[string]error) {
	t.Helper()
	opts.Reserved = Planned
	opts.SetaVersion = "v9.9.9"
	plugins, errs := Load(context.Background(), opts)
	ps := map[string]*Plugin{}
	for _, p := range plugins {
		ps[p.Name] = p
	}
	es := map[string]error{}
	for _, err := range errs {
		var pe *Error
		if !errors.As(err, &pe) {
			es[""] = err
			continue
		}
		es[pe.Name] = err
	}
	return ps, es
}

func TestLoad(t *testing.T) {
	dir, pathDir := t.TempDir(), t.TempDir()
	checktest.InstallSelf(t, dir, "good", "proto2", "liar", "foreign", "email", "hang", "active")
	checktest.InstallSelf(t, pathDir, "good", "other")
	if runtime.GOOS != "windows" {
		os.WriteFile(filepath.Join(dir, Prefix+"notexec"), []byte("#!/bin/sh\n"), 0o644)
		os.WriteFile(filepath.Join(dir, Prefix+"Bad-Name"), []byte("#!/bin/sh\n"), 0o755)
	}

	missing := filepath.Join(dir, "missing")
	ps, es := load(t, Options{Dirs: []string{dir, missing}, PATH: pathDir + string(os.PathListSeparator) + "relative" + string(os.PathListSeparator) + missing,
		DescribeTimeout: 2 * time.Second})

	names := slices.Sorted(func(yield func(string) bool) {
		for n := range ps {
			yield(n)
		}
	})
	if !slices.Equal(names, []string{"active", "good", "other"}) {
		t.Errorf("loaded %v", names)
	}
	good := ps["good"]
	if good.Version != "1.2.3" || len(good.Checks) != 9 || filepath.Dir(good.Path) != dir || len(good.Shadowed) != 1 {
		t.Errorf("good = %+v", good)
	}
	if m := ps["active"].Checks[0].Meta(); m.Mode != core.Active || m.Timeout != 3*time.Second || m.Module != "active" {
		t.Errorf("active meta = %+v", m)
	}
	want := map[string]string{
		"proto2":  "speaks protocol 2",
		"liar":    `describes itself as "other"`,
		"foreign": `must start with "foreign."`,
		"email":   "built-in module",
		"hang":    "describe timed out",
		"":        "plugins directory: open " + missing,
	}
	if runtime.GOOS != "windows" {
		want["Bad-Name"] = "invalid name"
	}
	for name, msg := range want {
		if err := es[name]; err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: error %v, want %q", name, err, msg)
		}
	}
	if len(es) != len(want) {
		t.Errorf("errors: %v", es)
	}
}

func runCheck(t *testing.T, p *Plugin, id string, target core.Target, timeout time.Duration) ([]core.Finding, error) {
	t.Helper()
	for _, c := range p.Checks {
		if c.Meta().ID == id {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return c.Run(ctx, core.Env{}, target)
		}
	}
	t.Fatalf("no check %s", id)
	return nil, nil
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	checktest.InstallSelf(t, dir, "good")
	ps, _ := load(t, Options{Dirs: []string{dir}, LookupEnv: env(map[string]string{"SETA_TG_TOKEN": "secret"})})
	p := ps["good"]
	target := core.Target{Kind: core.KindDomain, Name: "example.com", Plugins: map[string][]byte{"good": []byte(`{"subject":"www"}`)}}

	// Parallel: a race-enabled plugin sleeps 1s on exit.
	check := func(id string, target core.Target, timeout time.Duration, verify func(*testing.T, []core.Finding, error)) {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			fs, err := runCheck(t, p, id, target, timeout)
			verify(t, fs, err)
		})
	}
	check("good.x.finding", target, 10*time.Second, func(t *testing.T, fs []core.Finding, err error) {
		if err != nil || len(fs) != 1 || fs[0].Subject != "www" || fs[0].Severity != core.SeverityHigh ||
			fs[0].Evidence["target"] != "example.com" || fs[0].Evidence["deadline"] != "true" {
			t.Errorf("%+v, %v", fs, err)
		}
	})
	check("good.x.env", target, 10*time.Second, func(t *testing.T, fs []core.Finding, err error) {
		if err != nil || fs[0].Evidence["leaked"] != "false" || fs[0].Evidence["protocol"] != "1" || fs[0].Evidence["version"] != "v9.9.9" {
			t.Errorf("%+v, %v", fs, err)
		}
	})
	check("good.x.ok", core.Target{Kind: core.KindDomain, Name: "a.test"}, 10*time.Second, func(t *testing.T, fs []core.Finding, err error) {
		if err != nil || len(fs) != 0 {
			t.Errorf("%+v, %v", fs, err)
		}
	})
	for id, msg := range map[string]string{
		"good.x.fail":   "plugin: lookup failed",
		"good.x.junk":   "invalid JSON on stdout",
		"good.x.crash":  "plugin exited with status 3: boom",
		"good.x.badsev": `unknown severity "severe"`,
		"good.x.two":    "more than one JSON document",
	} {
		check(id, target, 10*time.Second, func(t *testing.T, _ []core.Finding, err error) {
			if err == nil || !strings.Contains(err.Error(), msg) {
				t.Errorf("%v, want %q", err, msg)
			}
		})
	}
	start := time.Now()
	check("good.x.slow", target, 300*time.Millisecond, func(t *testing.T, _ []core.Finding, err error) {
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Errorf("%v after %s", err, time.Since(start))
		}
	})
}

func TestCapped(t *testing.T) {
	c := &capped{max: 4}
	c.Write([]byte("ab"))
	if n, err := c.Write([]byte("cdef")); n != 4 || err != nil || c.String() != "abcd" || !c.over {
		t.Errorf("capped = %q over=%v", c.String(), c.over)
	}
}
