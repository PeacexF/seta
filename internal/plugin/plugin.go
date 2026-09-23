// Package plugin discovers exec plugins (seta-plugin-<name> executables)
// and runs their checks over protocol v1, defined in package sdk.
package plugin

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/sdk"
)

const Prefix = "seta-plugin-"

// Planned is the built-in modules on the roadmap; plugins can't take their
// names even before they ship.
var Planned = []string{"email", "tls", "http", "dns", "domain", "exposure", "ct"}

type Options struct {
	// Dirs are searched before PATH, in order.
	Dirs []string
	// PATH is a list of directories as in $PATH; relative entries are skipped.
	PATH string
	// Reserved are module names plugins may not use.
	Reserved []string
	// LookupEnv reads the environment plugins inherit a minimal part of.
	// Nil means os.LookupEnv.
	LookupEnv   func(string) (string, bool)
	SetaVersion string
	// DescribeTimeout defaults to 10s.
	DescribeTimeout time.Duration
}

type Plugin struct {
	Name    string
	Version string
	Path    string
	// Shadowed lists executables of the same name found later in the search.
	Shadowed []string
	Checks   []core.Check

	env         []string
	setaVersion string
}

// Error is a plugin that was found but can't be used.
type Error struct {
	Name, Path string
	Err        error
}

func (e *Error) Error() string { return fmt.Sprintf("plugin %s (%s): %v", e.Name, e.Path, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type candidate struct {
	name, path string
	shadowed   []string
}

// Load finds every plugin and asks each to describe itself. Plugins that
// fail are returned as errors; the others are usable.
func Load(ctx context.Context, opts Options) ([]*Plugin, []error) {
	cands, errs := discover(opts)
	env := minimalEnv(lookupEnv(opts), opts.SetaVersion)
	plugins := make([]*Plugin, len(cands))
	loadErrs := make([]error, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Go(func() {
			p := &Plugin{Name: c.name, Path: c.path, Shadowed: c.shadowed, env: env, setaVersion: opts.SetaVersion}
			if err := p.describe(ctx, opts); err != nil {
				loadErrs[i] = &Error{Name: c.name, Path: c.path, Err: err}
				return
			}
			plugins[i] = p
		})
	}
	wg.Wait()
	var out []*Plugin
	for i, p := range plugins {
		if p != nil {
			out = append(out, p)
		} else {
			errs = append(errs, loadErrs[i])
		}
	}
	return out, errs
}

func discover(opts Options) ([]candidate, []error) {
	dirs := slices.Clone(opts.Dirs)
	for _, d := range filepath.SplitList(opts.PATH) {
		if filepath.IsAbs(d) {
			dirs = append(dirs, d)
		}
	}
	pathext := ".COM;.EXE;.BAT;.CMD"
	if v, ok := lookupEnv(opts)("PATHEXT"); ok && v != "" {
		pathext = v
	}

	var (
		cands []candidate
		errs  []error
		index = map[string]int{}
		seen  = map[string]bool{}
	)
	for i, dir := range dirs {
		if seen[filepath.Clean(dir)] {
			continue
		}
		seen[filepath.Clean(dir)] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			// PATH often names directories that don't exist; a configured
			// directory that doesn't is likely a typo.
			if i < len(opts.Dirs) {
				errs = append(errs, fmt.Errorf("plugins directory: %w", err))
			}
			continue
		}
		for _, e := range entries {
			base, ok := strings.CutPrefix(e.Name(), Prefix)
			if !ok {
				continue
			}
			path := filepath.Join(dir, e.Name())
			name, ok := executable(path, base, pathext)
			if !ok {
				continue
			}
			if !namePattern.MatchString(name) {
				errs = append(errs, &Error{Name: name, Path: path,
					Err: errors.New("invalid name: want lowercase letters, digits and underscores after " + Prefix)})
				continue
			}
			if i, dup := index[name]; dup {
				cands[i].shadowed = append(cands[i].shadowed, path)
				continue
			}
			index[name] = len(cands)
			cands = append(cands, candidate{name: name, path: path})
		}
	}
	return cands, errs
}

// executable reports whether path can be run as a plugin and returns the
// plugin name: base without the extension on Windows, where PATHEXT decides
// what runs.
func executable(path, base, pathext string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	if runtime.GOOS == "windows" {
		ext := filepath.Ext(base)
		for _, e := range filepath.SplitList(pathext) {
			if ext != "" && strings.EqualFold(ext, e) {
				return strings.TrimSuffix(base, ext), true
			}
		}
		return "", false
	}
	return base, info.Mode().Perm()&0o111 != 0
}

// envKeys are passed through to plugins; everything else, notifier secrets
// in particular, is withheld.
var envKeys = []string{
	"PATH", "HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	// Windows programs fail in odd ways without these.
	"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
}

func minimalEnv(lookup func(string) (string, bool), setaVersion string) []string {
	var env []string
	for _, k := range envKeys {
		if v, ok := lookup(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, fmt.Sprintf("%s=%d", sdk.EnvProtocol, sdk.Protocol), sdk.EnvVersion+"="+setaVersion)
}

func (p *Plugin) describe(ctx context.Context, opts Options) error {
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(opts.DescribeTimeout, 10*time.Second))
	defer cancel()
	out, _, err := invoke(ctx, p.Path, "describe", nil, p.env)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("describe timed out")
	} else if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	var d sdk.Describe
	if err := decodeOne(out, &d); err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	if d.Protocol != sdk.Protocol {
		return fmt.Errorf("speaks protocol %d; this version of seta speaks %d", d.Protocol, sdk.Protocol)
	}
	if d.Name != p.Name {
		return fmt.Errorf("describes itself as %q; rename it to %s%s or fix its name", d.Name, Prefix, d.Name)
	}
	if slices.Contains(opts.Reserved, p.Name) {
		return fmt.Errorf("%q is the name of a built-in module", p.Name)
	}
	if len(d.Checks) == 0 {
		return errors.New("describes no checks")
	}
	p.Version = d.Version
	ids := map[string]bool{}
	for _, ci := range d.Checks {
		m, err := p.meta(ci)
		if err != nil {
			return err
		}
		if ids[m.ID] {
			return fmt.Errorf("check %s is described twice", m.ID)
		}
		ids[m.ID] = true
		p.Checks = append(p.Checks, &check{meta: m, plugin: p})
	}
	return nil
}

// maxTimeout keeps a plugin from holding up a run indefinitely.
const maxTimeout = 10 * time.Minute

func (p *Plugin) meta(ci sdk.CheckInfo) (core.Meta, error) {
	m := core.Meta{ID: ci.ID, Module: p.Name, Title: ci.Title, Description: ci.Description,
		Remediation: ci.Remediation, References: ci.References}
	if !strings.HasPrefix(ci.ID, p.Name+".") {
		return m, fmt.Errorf("check ID %q must start with %q", ci.ID, p.Name+".")
	}
	switch ci.Mode {
	case sdk.Passive:
		m.Mode = core.Passive
	case sdk.Active:
		m.Mode = core.Active
	default:
		return m, fmt.Errorf("check %s: invalid mode %q (want passive or active)", ci.ID, ci.Mode)
	}
	sev, err := core.ParseSeverity(string(ci.Severity))
	if err != nil {
		return m, fmt.Errorf("check %s: %w", ci.ID, err)
	}
	m.Severity = sev
	if ci.Timeout != "" {
		d, err := time.ParseDuration(ci.Timeout)
		if err != nil || d <= 0 || d > maxTimeout {
			return m, fmt.Errorf("check %s: invalid timeout %q (want a duration up to %s)", ci.ID, ci.Timeout, maxTimeout)
		}
		m.Timeout = d
	}
	return m, m.Validate()
}

// decodeOne decodes exactly one JSON document, surrounded only by whitespace.
func decodeOne(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("printed nothing on stdout")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON on stdout: %w", err)
	}
	if dec.More() {
		return errors.New("printed more than one JSON document on stdout")
	}
	return nil
}

type check struct {
	meta   core.Meta
	plugin *Plugin
}

func (c *check) Meta() core.Meta { return c.meta }

// maxLogLines caps how much of a plugin's stderr goes to the log per run.
const maxLogLines = 50

func (c *check) Run(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	p := c.plugin
	cfg := json.RawMessage(t.Plugins[p.Name])
	if cfg == nil {
		cfg = json.RawMessage("{}")
	}
	req := sdk.Request{Protocol: sdk.Protocol, Check: c.meta.ID, Target: sdk.Target{Kind: string(t.Kind), Name: t.Name},
		Config: cfg, SetaVersion: p.setaVersion}
	if dl, ok := ctx.Deadline(); ok {
		req.Deadline = dl.UTC()
	}
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, logs, err := invoke(ctx, p.Path, "run", in, p.env)
	if env.Logger != nil {
		sc := bufio.NewScanner(bytes.NewReader(logs))
		for n := 0; n < maxLogLines && sc.Scan(); n++ {
			env.Logger.Debug("plugin log", "plugin", p.Name, "line", sc.Text())
		}
	}
	if err != nil {
		return nil, err
	}
	var resp sdk.Response
	if err := decodeOne(out, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("plugin: %s", cmp.Or(truncate(*resp.Error, 500), "error without a message"))
	}
	findings := make([]core.Finding, 0, len(resp.Findings))
	for _, f := range resp.Findings {
		cf := core.Finding{Subject: f.Subject, Title: f.Title, Evidence: f.Evidence, Remediation: f.Remediation, References: f.References}
		if f.Severity != "" {
			if cf.Severity, err = core.ParseSeverity(string(f.Severity)); err != nil {
				return nil, fmt.Errorf("plugin returned a finding with %w", err)
			}
		}
		findings = append(findings, cf)
	}
	return findings, nil
}

func lookupEnv(opts Options) func(string) (string, bool) {
	if opts.LookupEnv == nil {
		return os.LookupEnv
	}
	return opts.LookupEnv
}
