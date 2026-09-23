package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"go.yaml.in/yaml/v3"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/registry"
	"github.com/PeacexF/seta/internal/state"
)

type Options struct {
	// Registry resolves check IDs and patterns.
	Registry *registry.Registry
	// LookupEnv resolves ${VAR} references. Nil means os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Plugins are the installed plugins' names, which plugins: may configure.
	Plugins []string
}

// Error is one problem in a config file. Line and Column are 1-based; zero
// means unknown.
type Error struct {
	Line, Column int
	Msg          string
}

// Errors lists every problem found in one config file, in file order.
type Errors struct {
	Path string
	List []Error
}

func (e *Errors) Error() string {
	lines := make([]string, len(e.List))
	for i, x := range e.List {
		pos := e.Path
		if x.Line > 0 {
			pos += ":" + strconv.Itoa(x.Line)
			if x.Column > 0 {
				pos += ":" + strconv.Itoa(x.Column)
			}
		}
		lines[i] = pos + ": " + x.Msg
	}
	return strings.Join(lines, "\n")
}

func Load(path string, opts Options) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data, opts)
}

// Parse decodes and validates a config. Any error it returns for the
// content of data is an *Errors.
func Parse(path string, data []byte, opts Options) (*Config, error) {
	p := &parser{lookupEnv: opts.LookupEnv, reg: opts.Registry, plugins: opts.Plugins}
	if p.lookupEnv == nil {
		p.lookupEnv = os.LookupEnv
	}
	c, err := p.parse(data)
	if len(p.errs) > 0 {
		slices.SortStableFunc(p.errs, func(a, b Error) int { return a.Line - b.Line })
		return nil, &Errors{Path: path, List: p.errs}
	}
	if err != nil {
		return nil, err
	}
	c.Path = path
	c.PluginsDir = resolveDir(path, c.PluginsDir)
	return c, nil
}

// PluginsDir reads just plugins_dir from the config at path, so plugins can
// be loaded before the config's check selections are validated against
// them. Problems are left for Load to report.
func PluginsDir(path string, lookupEnv func(string) (string, bool)) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 {
		return ""
	}
	n := value(doc.Content[0], "plugins_dir")
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	p := &parser{lookupEnv: lookupEnv}
	if p.lookupEnv == nil {
		p.lookupEnv = os.LookupEnv
	}
	dir, err := p.expand(n.Value)
	if err != nil {
		return ""
	}
	return resolveDir(path, dir)
}

func resolveDir(configPath, dir string) string {
	if dir == "" || filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(filepath.Dir(configPath), dir)
}

type parser struct {
	lookupEnv func(string) (string, bool)
	reg       *registry.Registry
	plugins   []string
	errs      []Error
}

func (p *parser) errorf(n *yaml.Node, format string, args ...any) {
	e := Error{Msg: fmt.Sprintf(format, args...)}
	if n != nil {
		e.Line, e.Column = n.Line, n.Column
	}
	p.errs = append(p.errs, e)
}

var yamlLine = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)

// yamlError records an error from the yaml package, keeping its line number.
func (p *parser) yamlError(msg string) {
	e := Error{Msg: strings.TrimPrefix(msg, "yaml: ")}
	if m := yamlLine.FindStringSubmatch(msg); m != nil {
		e.Line, _ = strconv.Atoi(m[1])
		e.Msg = m[2]
	}
	p.errs = append(p.errs, e)
}

func (p *parser) parse(data []byte) (*Config, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		p.yamlError(err.Error())
		return nil, nil
	}
	if len(doc.Content) == 0 {
		p.errorf(nil, "config is empty; start from 'seta init'")
		return nil, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		p.errorf(root, "config must be a mapping of settings, starting with \"version: %d\"", Version)
		return nil, nil
	}

	p.interpolate(root)
	p.checkFields(root, reflect.TypeFor[Config]())
	if len(p.errs) > 0 {
		return nil, nil
	}
	var c Config
	if err := root.Decode(&c); err != nil {
		if te, ok := errors.AsType[*yaml.TypeError](err); ok {
			for _, msg := range te.Errors {
				p.yamlError(msg)
			}
			return nil, nil
		}
		return nil, err
	}
	p.validate(&c, root)
	return &c, nil
}

// interpolate replaces ${VAR} in scalar values (never keys or comments).
// "$${" is a literal "${".
func (p *parser) interpolate(n *yaml.Node) {
	switch n.Kind {
	case yaml.SequenceNode:
		for _, c := range n.Content {
			p.interpolate(c)
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			p.interpolate(n.Content[i])
		}
	case yaml.ScalarNode:
		if !strings.Contains(n.Value, "${") {
			return
		}
		v, err := p.expand(n.Value)
		if err != nil {
			p.errorf(n, "%v", err)
			return
		}
		n.Value = v
		if n.Style == 0 {
			// Unquoted values are retyped after substitution, so that
			// "active: ${ACTIVE}" can become a boolean.
			n.Tag = ""
		}
	}
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (p *parser) expand(s string) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		if i > 0 && s[i-1] == '$' {
			b.WriteString(s[:i-1] + "${")
			s = s[i+2:]
			continue
		}
		b.WriteString(s[:i])
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated ${ in %q (write $${ for a literal ${)", s[i:])
		}
		name := s[i+2 : i+end]
		if !envName.MatchString(name) {
			return "", fmt.Errorf("invalid environment variable name ${%s}", name)
		}
		v, ok := p.lookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		b.WriteString(v)
		s = s[i+end+1:]
	}
}

// notYet names settings from the documented design that this version does
// not implement, so copying an example gives a clear message.
var notYet = map[string]bool{"include": true}

var unmarshalerType = reflect.TypeFor[yaml.Unmarshaler]()

// checkFields reports keys that don't correspond to a field of t, since
// yaml.v3's KnownFields is not available when decoding from a Node.
func (p *parser) checkFields(n *yaml.Node, t reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return
	}
	switch {
	case t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		for _, c := range n.Content {
			p.checkFields(c, t.Elem())
		}
	case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode:
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			ft, ok := fields[k.Value]
			switch {
			case ok:
				p.checkFields(n.Content[i+1], ft)
			case k.Value == "<<":
				// Merge keys are resolved by the decoder.
			case t == reflect.TypeFor[Config]() && notYet[k.Value]:
				p.errorf(k, "%q is not supported by this version of seta", k.Value)
			default:
				msg := fmt.Sprintf("unknown setting %q", k.Value)
				if s := suggest(k.Value, fields); s != "" {
					msg += fmt.Sprintf(" (did you mean %q?)", s)
				}
				p.errorf(k, "%s", msg)
			}
		}
	}
}

func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type)
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			out[name] = f.Type
		}
	}
	return out
}

func suggest(key string, fields map[string]reflect.Type) string {
	best, bestDist := "", 3
	for name := range fields {
		if d := editDistance(key, name); d < bestDist || d == bestDist && name < best {
			best, bestDist = name, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// value returns the value node for key in mapping n, or nil.
func value(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func item(n *yaml.Node, i int) *yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode || i >= len(n.Content) {
		return n
	}
	return n.Content[i]
}

// nodeOr returns n, or fallback when n is nil, so errors about absent
// settings point at their parent.
func nodeOr(n, fallback *yaml.Node) *yaml.Node {
	if n == nil {
		return fallback
	}
	return n
}

func (p *parser) validate(c *Config, root *yaml.Node) {
	switch v := value(root, "version"); {
	case v == nil:
		p.errorf(root, "missing \"version: %d\" at the top of the config", Version)
	case c.Version != Version:
		p.errorf(v, "unsupported config version %d (this version of seta reads version %d)", c.Version, Version)
	}

	servers := value(value(root, "resolver"), "servers")
	for i, s := range c.Resolver.Servers {
		if err := validResolver(s); err != nil {
			p.errorf(item(servers, i), "%v", err)
		}
	}
	p.patterns(value(value(root, "defaults"), "checks"), root, c.Defaults.Checks)

	targets := value(root, "targets")
	if len(c.Targets) == 0 {
		p.errorf(nodeOr(targets, root), "no targets; add at least one under \"targets:\", e.g. \"- domain: example.com\"")
	}
	firstLine := make(map[string]int)
	for i := range c.Targets {
		p.target(&c.Targets[i], item(targets, i), firstLine)
	}

	p.overrides(c, value(root, "severity_overrides"))

	sups := value(root, "suppressions")
	for i := range c.Suppressions {
		p.suppression(&c.Suppressions[i], item(sups, i), firstLine)
	}

	p.pluginConfigs(c.Plugins, value(root, "plugins"))
	p.state(&c.State, value(root, "state"))
	names := make(map[string]int)
	nots := value(root, "notify")
	for i := range c.Notify {
		p.notifier(&c.Notify[i], item(nots, i), names)
	}
	if c.Schedule == "" {
		c.Schedule = DefaultSchedule
	} else if _, err := cron.ParseStandard(c.Schedule); err != nil {
		p.errorf(value(root, "schedule"), "invalid schedule %q: %v (want cron syntax like \"0 */6 * * *\" or \"@every 6h\")", c.Schedule, err)
	}
}

func (p *parser) state(s *State, n *yaml.Node) {
	if s.Path == "" {
		s.Path = DefaultStatePath
	}
	switch {
	case s.ResolveAfter == 0:
		s.ResolveAfter = DefaultResolveAfter
	case s.ResolveAfter < 1:
		p.errorf(value(n, "resolve_after"), "resolve_after must be at least 1")
	}
	if s.Retention == 0 {
		s.Retention = DefaultRetention
	} else if time.Duration(s.Retention) < 24*time.Hour {
		p.errorf(value(n, "retention"), "retention must be at least 1d")
	}
}

// notifierFields lists the type-specific fields each type requires and
// accepts; any other type-specific field is an error.
var notifierFields = map[string]struct{ required, optional []string }{
	"telegram": {required: []string{"bot_token", "chat_id"}},
	"discord":  {required: []string{"webhook"}},
	"slack":    {required: []string{"webhook"}},
	"email":    {required: []string{"host", "from", "to"}, optional: []string{"port", "tls", "username", "password"}},
	"webhook":  {required: []string{"url"}, optional: []string{"secret", "format", "block_private_ips"}},
}

var telegramToken = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)

func (p *parser) notifier(nt *Notifier, n *yaml.Node, names map[string]int) {
	nt.Line = n.Line
	fields, ok := notifierFields[nt.Type]
	if !ok {
		p.errorf(nodeOr(value(n, "type"), n), "unknown notifier type %q (want telegram, discord, slack, email or webhook)", nt.Type)
		return
	}
	if nt.Name == "" {
		nt.Name = nt.Type
	}
	if line, dup := names[nt.Name]; dup {
		p.errorf(n, "two notifiers are named %q (the other on line %d); give them distinct names with \"name:\"", nt.Name, line)
	}
	names[nt.Name] = n.Line

	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if !isTypeField(k.Value) || slices.Contains(fields.required, k.Value) || slices.Contains(fields.optional, k.Value) {
			continue
		}
		p.errorf(k, "%q does not apply to %s notifiers", k.Value, nt.Type)
	}
	for _, f := range fields.required {
		if v := value(n, f); v == nil || v.Value == "" && v.Kind == yaml.ScalarNode || v.Kind == yaml.SequenceNode && len(v.Content) == 0 {
			p.errorf(nodeOr(v, n), "%s notifier needs %q", nt.Type, f)
		}
	}

	on := value(n, "on")
	for i, k := range nt.On {
		if _, ok := state.ParseKind(k); !ok {
			p.errorf(item(on, i), "unknown change %q in on (want new, regressed, resolved or persisting)", k)
		}
	}
	if nt.MinSeverity != "" {
		sev, err := core.ParseSeverity(nt.MinSeverity)
		if err != nil {
			p.errorf(value(n, "min_severity"), "%v", err)
		}
		nt.Severity = sev
	}
	if nt.Heartbeat != 0 && time.Duration(nt.Heartbeat) < time.Hour {
		p.errorf(value(n, "heartbeat"), "heartbeat must be at least 1h")
	}

	switch nt.Type {
	case "telegram":
		if nt.BotToken != "" && !telegramToken.MatchString(nt.BotToken) {
			p.errorf(value(n, "bot_token"), "bot_token doesn't look like a Telegram bot token (123456:ABC-...)")
		}
	case "discord":
		if nt.Webhook != "" && !discordWebhook.MatchString(nt.Webhook) {
			p.errorf(value(n, "webhook"), "webhook must be a Discord webhook URL (https://discord.com/api/webhooks/...)")
		}
	case "slack":
		if nt.Webhook != "" && !slackWebhook.MatchString(nt.Webhook) {
			p.errorf(value(n, "webhook"), "webhook must be a Slack incoming webhook URL (https://hooks.slack.com/services/...)")
		}
	case "email":
		p.email(nt, n)
	case "webhook":
		if nt.URL != "" {
			if u, err := url.Parse(nt.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				p.errorf(value(n, "url"), "url must be an http(s) URL")
			}
		}
		if nt.Format != "" && nt.Format != "json" {
			p.errorf(value(n, "format"), "unknown format %q (only json is supported)", nt.Format)
		}
	}
}

var slackWebhook = regexp.MustCompile(`^https://hooks\.slack(-gov)?\.com/services/[A-Za-z0-9_/-]+$`)

func (p *parser) email(nt *Notifier, n *yaml.Node) {
	if nt.Host != "" {
		if _, err := netip.ParseAddr(nt.Host); err != nil {
			if _, err := core.ParseDomain(nt.Host); err != nil && nt.Host != "localhost" {
				p.errorf(value(n, "host"), "host must be a host name or IP address, without a port (set port: separately)")
			}
		}
	}
	switch nt.TLS {
	case "":
		nt.TLS = TLSStartTLS
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		p.errorf(value(n, "tls"), "unknown tls %q (want starttls, tls or none)", nt.TLS)
	}
	if nt.Port == 0 {
		nt.Port = map[string]int{TLSStartTLS: 587, TLSImplicit: 465, TLSNone: 25}[nt.TLS]
	} else if nt.Port < 1 || nt.Port > 65535 {
		p.errorf(value(n, "port"), "port must be between 1 and 65535")
	}
	if (nt.Username == "") != (nt.Password == "") {
		p.errorf(nodeOr(value(n, "password"), value(n, "username")), "username and password must be set together")
	}
	if nt.Password != "" && nt.TLS == TLSNone {
		p.errorf(value(n, "tls"), "tls: none would send the password in clear text")
	}
	if nt.From != "" {
		if _, err := mail.ParseAddress(nt.From); err != nil {
			p.errorf(value(n, "from"), "invalid from address %q", nt.From)
		}
	}
	to := value(n, "to")
	for i, addr := range nt.To {
		if _, err := mail.ParseAddress(addr); err != nil {
			p.errorf(item(to, i), "invalid to address %q", addr)
		}
	}
}

var discordWebhook = regexp.MustCompile(`^https://(discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+$`)

func isTypeField(key string) bool {
	for _, f := range notifierFields {
		if slices.Contains(f.required, key) || slices.Contains(f.optional, key) {
			return true
		}
	}
	return false
}

func validResolver(spec string) error {
	if spec == "system" || dnsx.Presets[spec] != nil {
		return nil
	}
	_, err := dnsx.ParseServer(spec)
	return err
}

// patterns validates a check selection: each pattern on its own, then the
// whole list, which must select something.
func (p *parser) patterns(n, parent *yaml.Node, patterns []string) {
	if patterns == nil {
		return
	}
	ok := true
	for i, pat := range patterns {
		if _, err := p.reg.Select([]string{pat}); err != nil {
			p.errorf(item(n, i), "%v", err)
			ok = false
		}
	}
	if !ok {
		return
	}
	if sel, err := p.reg.Select(patterns); err != nil {
		p.errorf(nodeOr(n, parent), "%v", err)
	} else if len(sel) == 0 {
		p.errorf(nodeOr(n, parent), "check patterns %q select no checks", patterns)
	}
}

func (p *parser) target(t *Target, n *yaml.Node, firstLine map[string]int) {
	t.Line = n.Line
	dn := value(n, "domain")
	if t.Domain == "" {
		p.errorf(n, "target is missing \"domain\"")
		return
	}
	parsed, err := core.ParseDomain(t.Domain)
	if err != nil {
		p.errorf(dn, "%v", err)
		return
	}
	t.Domain = parsed.Name
	if line, dup := firstLine[t.Domain]; dup {
		p.errorf(dn, "duplicate target %s (first declared on line %d)", t.Domain, line)
	} else {
		firstLine[t.Domain] = dn.Line
	}
	p.patterns(value(n, "checks"), n, t.Checks)
	p.pluginConfigs(t.Plugins, value(n, "plugins"))

	hosts := value(n, "hosts")
	for i, h := range t.Hosts {
		parsed, err := core.ParseHost(h)
		if err != nil {
			p.errorf(item(hosts, i), "invalid host: %v", err)
			continue
		}
		t.Hosts[i] = parsed.String()
	}
	urls := value(n, "urls")
	for i, raw := range t.URLs {
		if u, err := url.Parse(raw); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			p.errorf(item(urls, i), "invalid URL %q: want http(s)://host/path", raw)
		} else if _, err := core.ParseHost(u.Host); err != nil {
			p.errorf(item(urls, i), "invalid URL %q: %v", raw, err)
		}
	}

	email := value(n, "email")
	sels := value(email, "dkim_selectors")
	for i, s := range t.Email.DKIMSelectors {
		if _, err := core.ParseDomain(s + "._domainkey.example"); err != nil || s == "" {
			p.errorf(item(sels, i), "invalid DKIM selector %q", s)
		}
	}
	mxs := value(email, "expected_mx")
	for i, h := range t.Email.ExpectedMX {
		name, wildcard := strings.CutPrefix(h, "*.")
		parsed, err := core.ParseDomain(name)
		if err != nil {
			p.errorf(item(mxs, i), "invalid expected MX host: %v", err)
			continue
		}
		t.Email.ExpectedMX[i] = parsed.Name
		if wildcard {
			t.Email.ExpectedMX[i] = "*." + parsed.Name
		}
	}
	bls := value(email, "dnsbls")
	for i, z := range t.Email.DNSBLs {
		parsed, err := core.ParseDomain(z)
		if err != nil {
			p.errorf(item(bls, i), "invalid DNSBL zone: %v", err)
			continue
		}
		t.Email.DNSBLs[i] = parsed.Name
	}
}

func (p *parser) pluginConfigs(cfgs map[string]PluginConfig, n *yaml.Node) {
	for i := 0; n != nil && n.Kind == yaml.MappingNode && i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; !slices.Contains(p.plugins, k.Value) {
			p.errorf(k, "no plugin named %q is installed; 'seta plugins list' shows the plugins seta finds", k.Value)
		}
	}
}

func (p *parser) overrides(c *Config, n *yaml.Node) {
	if n == nil {
		return
	}
	canonical := make(SeverityOverrides, len(c.SeverityOverrides))
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		check, ok := p.reg.Lookup(k.Value)
		if !ok {
			p.errorf(k, "unknown check %q; run 'seta checks list' to see all checks", k.Value)
			continue
		}
		id := check.Meta().ID
		if _, dup := canonical[id]; dup {
			p.errorf(k, "%s is overridden more than once (possibly under a former ID)", id)
			continue
		}
		canonical[id] = c.SeverityOverrides[k.Value]
	}
	c.SeverityOverrides = canonical
}

func (p *parser) suppression(s *Suppression, n *yaml.Node, targets map[string]int) {
	s.Line = n.Line
	switch cn := value(n, "check"); {
	case s.Check == "":
		p.errorf(n, "suppression is missing \"check\"")
	case strings.HasPrefix(s.Check, "!"):
		p.errorf(cn, "suppression check %q cannot be an exclusion", s.Check)
	default:
		checks, err := p.reg.Select([]string{s.Check})
		if err != nil {
			p.errorf(cn, "%v", err)
			break
		}
		s.ids = make(map[string]bool, len(checks))
		for _, c := range checks {
			s.ids[c.Meta().ID] = true
		}
	}
	if s.Target != "" {
		tn := value(n, "target")
		parsed, err := core.ParseDomain(s.Target)
		switch {
		case err != nil:
			p.errorf(tn, "%v", err)
		case targets[parsed.Name] == 0:
			p.errorf(tn, "suppression target %s is not one of the configured targets", parsed.Name)
		default:
			s.Target = parsed.Name
		}
	}
	if strings.TrimSpace(s.Reason) == "" {
		p.errorf(nodeOr(value(n, "reason"), n), "suppression needs a \"reason\" explaining why the finding is accepted")
	}
}
