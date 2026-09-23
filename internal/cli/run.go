package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/baseline"
	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/report"
	"github.com/PeacexF/seta/internal/version"
)

// configRunFlags are shared by the commands that run a config.
type configRunFlags struct {
	config string
	active bool
	only   []string
	rf     resolverFlags
}

func (cf *configRunFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&cf.config, "config", "c", config.DefaultPath, "config file")
	f.BoolVar(&cf.active, "active", false, "also run active checks on targets that don't enable them")
	f.StringSliceVar(&cf.only, "only", nil, "further limit each target's checks to these patterns (e.g. 'email.spf.*')")
	cf.rf.register(cmd)
}

func (a *App) runCommand() *cobra.Command {
	var (
		cf configRunFlags
		of outputFlags
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the checks declared in a config file",
		Long: "Run every target in the config once and report the findings. Exit codes:\n" +
			"  0  no findings at or above --fail-on (after suppressions and --baseline)\n" +
			"  1  findings at or above --fail-on\n" +
			"  2  usage or config error\n" +
			"  3  checks could not complete and --strict is set",
		Example: "  seta run\n" +
			"  seta run -c seta.yaml --fail-on high\n" +
			"  seta run --baseline .seta-baseline.json --format sarif -o seta.sarif",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.openSession(cmd, of)
			if err != nil {
				return err
			}
			defer s.close()
			res, cfg, notes, err := a.runConfig(cmd, cf)
			if err != nil {
				return err
			}
			return a.finish(s, res, notes, sourceOf(cfg))
		},
	}
	cf.register(cmd)
	of.register(cmd, "low")
	return cmd
}

func (a *App) baselineCommand() *cobra.Command {
	var (
		cf     configRunFlags
		output string
	)
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Record current findings so that CI fails only on new ones",
		Long: "Run the config and write every current finding (except suppressed ones) to a baseline\n" +
			"file. Commit it, and pass it to 'seta run --baseline' so that only findings that are not\n" +
			"in the baseline are reported and fail the run.",
		Example: "  seta baseline\n" +
			"  seta run --baseline " + baseline.DefaultPath,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, _, _, err := a.runConfig(cmd, cf)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err := baseline.New(res.Findings).Write(&buf); err != nil {
				return err
			}
			if err := os.WriteFile(output, buf.Bytes(), 0o644); err != nil {
				return usageErr("%v", err)
			}
			fmt.Fprintf(a.Stderr, "Wrote %s to %s.\n", plural(len(res.Findings), "finding"), output)
			if n := len(res.Errors); n > 0 {
				fmt.Fprintf(a.Stderr, "warning: %s could not complete, so their findings are not in the baseline "+
					"and will be reported as new later.\n", plural(n, "check"))
			}
			return nil
		},
	}
	cf.register(cmd)
	cmd.Flags().StringVarP(&output, "output", "o", baseline.DefaultPath, "baseline file to write")
	return cmd
}

// loadConfig reads and validates the config, printing warnings about
// expired suppressions.
func (a *App) loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path, config.Options{Registry: a.Registry})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, usageErr("config %s does not exist; create one with 'seta init'", path)
		}
		return nil, &exitError{code: ExitUsage, err: err}
	}
	now := a.now()
	for _, s := range cfg.Suppressions {
		if s.Expired(now) {
			fmt.Fprintf(a.Stderr, "warning: %s:%d: suppression of %s expired on %s; its findings are reported again\n",
				cfg.Path, s.Line, s.Check, s.Expires.Format(time.DateOnly))
		}
	}
	return cfg, nil
}

// plan is a loaded config turned into engine jobs.
type plan struct {
	cfg   *config.Config
	jobs  []engine.Job
	notes []string
}

func (a *App) planConfig(cf configRunFlags) (*plan, error) {
	cfg, err := a.loadConfig(cf.config)
	if err != nil {
		return nil, err
	}
	var only map[string]bool
	if cf.only != nil {
		checks, err := a.Registry.Select(cf.only)
		if err != nil {
			return nil, usageErr("%v", err)
		}
		only = make(map[string]bool)
		for _, c := range checks {
			only[c.Meta().ID] = true
		}
	}

	p := &plan{cfg: cfg}
	skippedActive := 0
	for _, t := range cfg.Targets {
		selected, err := a.Registry.Select(cfg.CheckPatterns(t))
		if err != nil {
			return nil, usageErr("%v", err) // validated while loading
		}
		active := cf.active || cfg.ActiveFor(t)
		var checks []core.Check
		for _, c := range selected {
			m := c.Meta()
			switch {
			case only != nil && !only[m.ID]:
			case m.Mode == core.Active && !active:
				skippedActive++
			default:
				checks = append(checks, c)
			}
		}
		if len(checks) == 0 {
			p.notes = append(p.notes, fmt.Sprintf("%s: no checks selected.", t.Domain))
			continue
		}
		p.jobs = append(p.jobs, engine.Job{Target: targetOf(t), Checks: checks})
	}
	if len(p.jobs) == 0 {
		return nil, usageErr("no checks selected for any target")
	}
	if skippedActive > 0 {
		p.notes = append(p.notes, fmt.Sprintf("%s not run; set active: true on a target or pass --active.",
			plural(skippedActive, "active check")))
	}
	return p, nil
}

// newEngine sets up the resolver (flags win over the config) and returns
// an engine using it, along with the effective resolver settings.
func (a *App) newEngine(cmd *cobra.Command, cf configRunFlags, cfg *config.Config) (*engine.Engine, resolverFlags, error) {
	rf := cf.rf
	if !cmd.Flags().Changed("resolver") && len(cfg.Resolver.Servers) > 0 {
		rf.specs = cfg.Resolver.Servers
	}
	rf.skipCheck = rf.skipCheck || cfg.Resolver.SkipCheck
	rf.timeout = time.Duration(cfg.Resolver.Timeout)
	resolver, err := a.setupResolver(cmd.Context(), rf)
	if err != nil {
		return nil, rf, err
	}
	eng := &engine.Engine{Resolver: resolver, Logger: a.logger, CheckTimeout: time.Duration(cfg.Defaults.CheckTimeout)}
	eng.Net.UserAgent = version.UserAgent()
	return eng, rf, nil
}

// runConfig runs every target of the config once and applies its severity
// overrides and suppressions.
func (a *App) runConfig(cmd *cobra.Command, cf configRunFlags) (*engine.Result, *config.Config, []string, error) {
	p, err := a.planConfig(cf)
	if err != nil {
		return nil, nil, nil, err
	}
	eng, _, err := a.newEngine(cmd, cf, p.cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	res := eng.Run(cmd.Context(), p.jobs)
	p.cfg.Apply(res, a.now())
	return res, p.cfg, p.notes, nil
}

func targetOf(t config.Target) core.Target {
	return core.Target{
		Kind: core.KindDomain,
		Name: t.Domain,
		Email: core.EmailOptions{
			DKIMSelectors:  t.Email.DKIMSelectors,
			ExpectedMX:     t.Email.ExpectedMX,
			DNSBLs:         t.Email.DNSBLs,
			SpamhausDQSKey: os.Getenv("SETA_SPAMHAUS_DQS_KEY"),
		},
	}
}

// sourceOf points SARIF results at the lines declaring each target. Code
// scanning resolves paths against the repository root, which is where CI
// runs seta; absolute paths are made relative to the working directory.
func sourceOf(cfg *config.Config) *report.Source {
	path := cfg.Path
	if filepath.IsAbs(path) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, path); err == nil {
				path = rel
			}
		}
	}
	src := &report.Source{Path: path, TargetLines: make(map[string]int)}
	for _, t := range cfg.Targets {
		src.TargetLines[t.Domain] = t.Line
	}
	return src
}
