package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/version"
)

type scanFlags struct {
	active    bool
	only      []string
	selectors []string
}

func (a *App) scanCommand() *cobra.Command {
	var (
		rf resolverFlags
		sf scanFlags
		of outputFlags
	)
	cmd := &cobra.Command{
		Use:   "scan <domain>...",
		Short: "Scan domains once, without a config file",
		Long: "Run passive checks against the given domains and print a report. Active checks, which\n" +
			"probe the domain's servers (STARTTLS on port 25, old TLS versions, zone transfers, exposed\n" +
			"files), run only with --active.\n\n" +
			"Only scan domains you own or are authorized to test.",
		Example: "  seta scan example.com\n" +
			"  seta scan --active example.com example.org\n" +
			"  seta scan --only 'email.spf.*' --format json example.com\n" +
			"  seta scan --dkim-selector google,s1 example.com",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &exitError{code: ExitUsage, err: errors.New("scan needs at least one domain, e.g. 'seta scan example.com'")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runScan(cmd, args, rf, sf, of)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&sf.active, "active", false, "also run active checks, which connect to the domain's servers")
	f.StringSliceVar(&sf.only, "only", nil, "run only checks matching these patterns (e.g. 'email.spf.*', '!email.dnsbl.*')")
	f.StringSliceVar(&sf.selectors, "dkim-selector", nil, "DKIM selectors to check (default: try common selector names)")
	of.register(cmd, "none")
	rf.register(cmd)
	return cmd
}

func (a *App) runScan(cmd *cobra.Command, args []string, rf resolverFlags, sf scanFlags, of outputFlags) error {
	targets, err := parseTargets(args)
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	a.loadPlugins(cmd.Context(), "", false)
	checks, skippedActive, err := a.selectChecks(sf.only, sf.active)
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	for i := range targets {
		targets[i].Email = core.EmailOptions{
			DKIMSelectors:  sf.selectors,
			SpamhausDQSKey: os.Getenv("SETA_SPAMHAUS_DQS_KEY"),
		}
	}
	s, err := a.openSession(cmd, of)
	if err != nil {
		return err
	}
	defer s.close()

	resolver, err := a.setupResolver(cmd.Context(), rf)
	if err != nil {
		return err
	}
	jobs := make([]engine.Job, len(targets))
	for i, t := range targets {
		jobs[i] = engine.Job{Target: t, Checks: checks}
	}
	eng := &engine.Engine{Resolver: resolver, Logger: a.logger}
	eng.Net.UserAgent = version.UserAgent()
	res := eng.Run(cmd.Context(), jobs)

	var notes []string
	if skippedActive > 0 {
		notes = append(notes, fmt.Sprintf("%s not run; pass --active to probe the domain's servers.",
			plural(skippedActive, "active check")))
	}
	return a.finish(s, res, notes, nil)
}

// selectChecks applies --only and drops active checks unless --active is
// set. It errors when that leaves nothing to run.
func (a *App) selectChecks(only []string, active bool) (checks []core.Check, skippedActive int, err error) {
	selected, err := a.Registry.Select(only)
	if err != nil {
		return nil, 0, err
	}
	for _, c := range selected {
		if c.Meta().Mode == core.Active && !active {
			skippedActive++
			continue
		}
		checks = append(checks, c)
	}
	if len(checks) == 0 {
		if skippedActive > 0 {
			return nil, 0, fmt.Errorf("%s selects only active checks; pass --active to run them", strings.Join(only, ","))
		}
		return nil, 0, errors.New("no checks selected")
	}
	return checks, skippedActive, nil
}

// parseTargets validates domain arguments, dropping duplicates while keeping
// the order they were given in.
func parseTargets(args []string) ([]core.Target, error) {
	seen := make(map[string]bool)
	var targets []core.Target
	for _, arg := range args {
		t, err := core.ParseDomain(arg)
		if err != nil {
			return nil, err
		}
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		targets = append(targets, t)
	}
	return targets, nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
