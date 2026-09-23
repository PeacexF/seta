package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/seta/checks/email"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/registry"
)

func testRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	reg := registry.New()
	for _, c := range email.Checks() {
		if err := reg.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

var testEnv = map[string]string{"SETA_DOMAIN": "example.org", "SETA_ACTIVE": "true", "EMPTY": ""}

func parse(t *testing.T, src string) (*Config, error) {
	t.Helper()
	return Parse("seta.yaml", []byte(src), Options{
		Registry:  testRegistry(t),
		LookupEnv: func(k string) (string, bool) { v, ok := testEnv[k]; return v, ok },
		Plugins:   []string{"ipv6"},
	})
}

func TestFullConfig(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := parse(t, string(data))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || !slices.Equal(c.Resolver.Servers, []string{"doh", "9.9.9.9"}) ||
		c.Resolver.Timeout != Duration(3*time.Second) || c.Defaults.CheckTimeout != Duration(20*time.Second) {
		t.Errorf("resolver/defaults: %+v %+v", c.Resolver, c.Defaults)
	}
	if len(c.Targets) != 3 {
		t.Fatalf("targets: %+v", c.Targets)
	}
	a, b, e := c.Targets[0], c.Targets[1], c.Targets[2]
	if a.Domain != "example.com" || a.Line != 12 || !c.ActiveFor(a) || !slices.Equal(c.CheckPatterns(a), []string{"email.*", "!email.dnsbl.*"}) {
		t.Errorf("target 0: %+v", a)
	}
	if !slices.Equal(a.Email.ExpectedMX, []string{"aspmx.l.google.com", "*.mail.protection.outlook.com"}) ||
		!slices.Equal(a.Email.DKIMSelectors, []string{"google", "s1"}) {
		t.Errorf("target 0 email: %+v", a.Email)
	}
	if b.Domain != "example.org" || !c.ActiveFor(b) || !slices.Equal(c.CheckPatterns(b), []string{"email.spf.*"}) {
		t.Errorf("target 1 (interpolated): %+v", b)
	}
	if e.Domain != "xn--bcher-kva.example" || c.ActiveFor(e) || c.CheckPatterns(e) != nil {
		t.Errorf("target 2: %+v", e)
	}
	if c.SeverityOverrides["email.dmarc.policy_none"] != core.SeverityLow || len(c.SeverityOverrides) != 1 {
		t.Errorf("overrides: %v", c.SeverityOverrides)
	}
	s := c.Suppressions[0]
	if s.Target != "example.com" || s.Line != 32 || !s.Expires.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("suppression: %+v", s)
	}
	if !s.Matches(core.Finding{CheckID: "email.mtasts.missing", Target: "example.com"}) ||
		s.Matches(core.Finding{CheckID: "email.mtasts.missing", Target: "example.org"}) {
		t.Error("suppression matching")
	}
	if glob := c.Suppressions[1]; !glob.Matches(core.Finding{CheckID: "email.dkim.weak_key", Target: "example.org", Subject: "selector:k1"}) ||
		glob.Matches(core.Finding{CheckID: "email.dkim.weak_key", Target: "example.org", Subject: "selector:k2"}) {
		t.Error("glob suppression with subject")
	}
}

func TestErrors(t *testing.T) {
	const head = "version: 1\ntargets:\n  - domain: example.com\n"
	tests := []struct {
		name, src string
		want      []string // each "line: message fragment"
	}{
		{"empty", "", []string{"0: config is empty"}},
		{"not a mapping", "- a\n", []string{"1: must be a mapping"}},
		{"syntax", "version: [1\n", []string{"1: did not find expected"}},
		{"missing version", "targets:\n  - domain: example.com\n", []string{"1: missing \"version: 1\""}},
		{"wrong version", "version: 2\ntargets:\n  - domain: example.com\n", []string{"1: unsupported config version 2"}},
		{"no targets", "version: 1\n", []string{"1: no targets"}},
		{"unknown field with suggestion", head + "    chekcs: [\"email.*\"]\n", []string{`4: unknown setting "chekcs" (did you mean "checks"?)`}},
		{"unknown nested field", head + "    email:\n      selectors: [a]\n", []string{`5: unknown setting "selectors"`}},
		{"not yet", head + "include: x\n", []string{`4: "include" is not supported by this version`}},
		{"plugin problems", head + "    plugins:\n      nope: {a: 1}\nplugins:\n  ipv6x: {}\n",
			[]string{`5: no plugin named "nope" is installed`, `7: no plugin named "ipv6x"`}},
		{"plugin settings", head + "plugins:\n  ipv6: {a: {[1]: x}}\n  other: [a]\n",
			[]string{"5: plugin setting names must be plain strings", "6: plugin settings must be a mapping"}},
		{"bad schedule", head + "schedule: \"61 * * * *\"\n", []string{`4: invalid schedule "61 * * * *"`}},
		{"bad state", head + "state:\n  resolve_after: -1\n  retention: 12h\n",
			[]string{"5: resolve_after must be at least 1", "6: retention must be at least 1d"}},
		{"notifier problems", head + `notify:
  - type: pager
  - type: telegram
    webhook: https://discord.com/api/webhooks/1/x
    on: [new, fixed]
    min_severity: severe
    heartbeat: 10m
  - type: discord
    webhook: https://example.com/hook
  - type: webhook
    url: ftp://example.com
    format: xml
  - type: webhook
    url: https://example.com
`, []string{
			`5: unknown notifier type "pager"`,
			`6: telegram notifier needs "bot_token"`, `6: telegram notifier needs "chat_id"`,
			`7: "webhook" does not apply to telegram notifiers`,
			`8: unknown change "fixed"`, `9: unknown severity "severe"`, "10: heartbeat must be at least 1h",
			"12: webhook must be a Discord webhook URL",
			"14: url must be an http(s) URL", `15: unknown format "xml"`,
			`16: two notifiers are named "webhook" (the other on line 13)`,
		}},
		{"slack and email problems", head + `notify:
  - type: slack
    webhook: https://discord.com/api/webhooks/1/x
  - type: email
    host: smtp.example.com:587
    port: 70000
    tls: ssl
    username: me
    from: "not an address"
    to: [ops@example.com, "@nope"]
  - type: email
    name: plain
    host: localhost
    tls: none
    username: me
    password: pw
    from: seta@example.com
    to: []
`, []string{
			"6: webhook must be a Slack incoming webhook URL",
			"8: host must be a host name or IP address", "9: port must be between 1 and 65535", `10: unknown tls "ssl"`,
			"11: username and password must be set together", `12: invalid from address "not an address"`,
			`13: invalid to address "@nope"`,
			"17: tls: none would send the password in clear text", `21: email notifier needs "to"`,
		}},
		{"type errors collected", "version: one\ntargets:\n  - domain: example.com\n    active: maybe\n",
			[]string{"1: cannot unmarshal !!str `one` into int", "4: cannot unmarshal !!str `maybe` into bool"}},
		{"bare duration", head + "defaults:\n  check_timeout: 10\n", []string{"5: invalid duration \"10\""}},
		{"bad date", head + "suppressions:\n  - check: email.spf.missing\n    reason: x\n    expires: 2027-13-01\n", []string{"7: invalid date"}},
		{"bad severity", head + "severity_overrides:\n  email.spf.missing: severe\n", []string{`5: invalid severity "severe" for email.spf.missing`}},
		{"unset env", head + "resolver:\n  servers: [\"${NOPE}\"]\n", []string{"5: environment variable NOPE is not set"}},
		{"bad env syntax", head + "resolver:\n  servers: [\"${1X}\", \"${OPEN\"]\n", []string{"5: invalid environment variable name", "5: unterminated ${"}},
		{"bad resolver", head + "resolver:\n  servers: [udp://1.1.1.1]\n", []string{"5: "}},
		{"bad domain", "version: 1\ntargets:\n  - domain: https://example.com\n  - active: true\n",
			[]string{"3: \"https://example.com\" is not a domain name", "4: target is missing \"domain\""}},
		{"duplicate target", head + "  - domain: EXAMPLE.com.\n", []string{"4: duplicate target example.com (first declared on line 3)"}},
		{"duplicate key", head + "version: 1\n", []string{"4: mapping key \"version\" already defined"}},
		{"bad patterns", head + "    checks: [\"email.nope.*\", \"Email\"]\n",
			[]string{`4: check pattern "email.nope.*" matches no checks`, `4: invalid check pattern "Email"`}},
		{"selects nothing", head + "defaults:\n  checks: [\"!email.*\"]\n", []string{"5: check patterns [\"!email.*\"] select no checks"}},
		{"bad web options", head + "    hosts: [\"a.com:0\", \"https://a.com\", \"b.com:8443\"]\n    urls: [\"ftp://a.com\", \"https://u@a.com/\", \"https://a/\"]\n",
			[]string{`4: invalid host: "a.com:0" has an invalid port`, "4: invalid host", `5: invalid URL "ftp://a.com"`,
				`5: invalid URL "https://u@a.com/"`, `5: invalid URL "https://a/"`}},
		{"bad email options", head + "    email:\n      dkim_selectors: [\"a b\"]\n      expected_mx: [\"*.\"]\n      dnsbls: [\"bl\"]\n",
			[]string{`5: invalid DKIM selector "a b"`, "6: invalid expected MX host", "7: invalid DNSBL zone"}},
		{"unknown override", head + "severity_overrides:\n  email.spf.nope: low\n", []string{`5: unknown check "email.spf.nope"`}},
		{"suppression problems", head + "suppressions:\n  - target: other.com\n  - check: \"!email.*\"\n    reason: \" \"\n",
			[]string{`5: suppression is missing "check"`, "5: suppression target other.com is not one of the configured targets",
				`5: suppression needs a "reason"`, `6: suppression check "!email.*" cannot be an exclusion`, `7: suppression needs a "reason"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse(t, tt.src)
			errs, ok := errors.AsType[*Errors](err)
			if !ok {
				t.Fatalf("want *Errors, got %v", err)
			}
			if len(errs.List) != len(tt.want) {
				t.Fatalf("got %d errors, want %d:\n%v", len(errs.List), len(tt.want), err)
			}
			for i, w := range tt.want {
				line, frag, _ := strings.Cut(w, ": ")
				got := errs.List[i]
				if strconv.Itoa(got.Line) != line || !strings.Contains(got.Msg, frag) {
					t.Errorf("error %d = %d: %s; want %s", i, got.Line, got.Msg, w)
				}
			}
		})
	}
}

func TestPlugins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seta.yaml")
	src := `version: 1
plugins_dir: ${PLUGINS}
plugins:
  ipv6: {hosts: ["@", www], strict: true, since: 2027-01-01, n: 0x10, "on": yes}
targets:
  - domain: a.com
    plugins:
      ipv6: {hosts: [mail]}
  - domain: b.com
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	lookup := func(k string) (string, bool) { return "plugins", k == "PLUGINS" }
	if got := PluginsDir(path, lookup); got != filepath.Join(dir, "plugins") {
		t.Errorf("PluginsDir = %q", got)
	}
	c, err := Load(path, Options{Registry: testRegistry(t), LookupEnv: lookup, Plugins: []string{"ipv6"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.PluginsDir != filepath.Join(dir, "plugins") {
		t.Errorf("PluginsDir = %q", c.PluginsDir)
	}
	if got := string(c.PluginConfig(c.Targets[0])["ipv6"]); got != `{"hosts":["mail"],"n":16,"on":"yes","since":"2027-01-01","strict":true}` {
		t.Errorf("a.com config = %s", got)
	}
	if got := string(c.PluginConfig(c.Targets[1])["ipv6"]); got != `{"hosts":["@","www"],"n":16,"on":"yes","since":"2027-01-01","strict":true}` {
		t.Errorf("b.com config = %s", got)
	}

	c, err = parse(t, "version: 1\ntargets:\n  - domain: a.com\n    plugins: {ipv6: }\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(c.PluginConfig(c.Targets[0])["ipv6"]); got != "{}" {
		t.Errorf("empty config = %s", got)
	}
}

func TestDaemonSettings(t *testing.T) {
	c, err := parse(t, "version: 1\ntargets:\n  - domain: example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.State.Path != DefaultStatePath || c.State.ResolveAfter != 2 || c.State.Retention != DefaultRetention || c.Schedule != DefaultSchedule {
		t.Errorf("defaults: %+v %q", c.State, c.Schedule)
	}
	c, err = parse(t, `version: 1
targets:
  - domain: example.com
schedule: "@every 30m"
state:
  path: /var/lib/seta/state.db
  resolve_after: 3
  retention: 30d
notify:
  - type: telegram
    bot_token: "123456:ABC-def_1"
    chat_id: -1001234567890
    on: [new, regressed]
    min_severity: medium
    heartbeat: weekly
  - type: discord
    name: team
    webhook: https://discord.com/api/webhooks/123/abc-DEF
  - type: webhook
    url: https://hooks.example.com/seta
    secret: s3cret
    block_private_ips: true
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.State.ResolveAfter != 3 || c.State.Retention != Duration(30*24*time.Hour) || c.Schedule != "@every 30m" {
		t.Errorf("state: %+v %q", c.State, c.Schedule)
	}
	tg := c.Notify[0]
	if tg.Name != "telegram" || tg.ChatID != "-1001234567890" || tg.Severity != core.SeverityMedium ||
		tg.Heartbeat != Duration(7*24*time.Hour) || tg.Line != 10 {
		t.Errorf("telegram: %+v", tg)
	}
	if c.Notify[1].Name != "team" || !c.Notify[2].BlockPrivateIPs || c.Notify[2].Severity != core.SeverityUnset {
		t.Errorf("notifiers: %+v", c.Notify[1:])
	}
}

func TestErrorsFormat(t *testing.T) {
	_, err := parse(t, "version: 1\ntargets:\n  - domain: example.com\n    bogus: 1\n")
	if got, want := err.Error(), `seta.yaml:4:5: unknown setting "bogus"`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestInterpolation(t *testing.T) {
	c, err := parse(t, `version: 1
defaults:
  active: ${SETA_ACTIVE}
targets:
  - domain: "${SETA_DOMAIN}"
    email:
      dkim_selectors: ["s${EMPTY}1"]
suppressions:
  - check: email.spf.missing
    reason: "costs $${SETA_DOMAIN}, not ${SETA_DOMAIN}" # ${NOT_A_VAR}
`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Defaults.Active || c.Targets[0].Domain != "example.org" || c.Targets[0].Email.DKIMSelectors[0] != "s1" {
		t.Errorf("%+v", c)
	}
	if got, want := c.Suppressions[0].Reason, "costs ${SETA_DOMAIN}, not example.org"; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	// A quoted value stays a string even when it looks like a boolean.
	if _, err := parse(t, "version: 1\ndefaults:\n  active: \"${SETA_ACTIVE}\"\ntargets:\n  - domain: example.com\n"); err == nil ||
		!strings.Contains(err.Error(), "into bool") {
		t.Errorf("quoted bool: %v", err)
	}
	// Comments are never interpolated.
	if _, err := parse(t, "version: 1 # ${UNSET}\ntargets:\n  - domain: example.com\n"); err != nil {
		t.Error(err)
	}
}

func TestSuppressionAliasesAndApply(t *testing.T) {
	c, err := parse(t, `version: 1
targets:
  - domain: example.com
severity_overrides:
  email.mx.fcrdns: critical
suppressions:
  - check: email.spf.*
    reason: handled elsewhere
    expires: 2030-01-01
  - check: email.dmarc.policy_none
    reason: old exception
    expires: 2020-01-01
`)
	if err != nil {
		t.Fatal(err)
	}
	res := &engine.Result{Findings: []core.Finding{
		{CheckID: "email.dmarc.policy_none", Target: "example.com", Severity: core.SeverityMedium},
		{CheckID: "email.mx.fcrdns", Target: "example.com", Subject: "mx1", Severity: core.SeverityLow},
		{CheckID: "email.spf.missing", Target: "example.com", Severity: core.SeverityHigh},
	}}
	expired := c.Apply(res, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if len(expired) != 1 || expired[0].Check != "email.dmarc.policy_none" {
		t.Errorf("expired = %+v", expired)
	}
	if len(res.Findings) != 2 || res.Findings[0].CheckID != "email.mx.fcrdns" || res.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("findings = %+v", res.Findings)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != "handled elsewhere" || res.Suppressed[0].Expires.Year() != 2030 {
		t.Errorf("suppressed = %+v", res.Suppressed)
	}
	if !c.Suppressions[0].Expired(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("a suppression expires at the start of its date")
	}
}

func TestSeverityOverrideAlias(t *testing.T) {
	reg := registry.New()
	for _, c := range []core.Check{renamed{}} {
		if err := reg.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	src := "version: 1\ntargets:\n  - domain: example.com\nseverity_overrides:\n  email.old.name: info\n"
	c, err := Parse("seta.yaml", []byte(src), Options{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if c.SeverityOverrides["email.new.name"] != core.SeverityInfo {
		t.Errorf("override not canonicalized: %v", c.SeverityOverrides)
	}
	_, err = Parse("seta.yaml", []byte(src+"  email.new.name: low\n"), Options{Registry: reg})
	if err == nil || !strings.Contains(err.Error(), "overridden more than once") {
		t.Errorf("duplicate via alias: %v", err)
	}
}

type renamed struct{}

func (renamed) Meta() core.Meta {
	return core.Meta{ID: "email.new.name", Aliases: []string{"email.old.name"}, Module: "email", Title: "x", Severity: core.SeverityLow}
}

func (renamed) Run(context.Context, core.Env, core.Target) ([]core.Finding, error) { return nil, nil }
