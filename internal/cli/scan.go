package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
	"github.com/PeacexF/seta/internal/report"
)

func (a *App) scanCommand() *cobra.Command {
	var rf resolverFlags
	cmd := &cobra.Command{
		Use:   "scan <domain>...",
		Short: "Scan domains once, without a config file",
		Long: "Run all passive checks against the given domains and print a report.\n\n" +
			"Only scan domains you own or are authorized to test.",
		Example: "  seta scan example.com\n  seta scan example.com example.org\n  seta scan --resolver doh example.com",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &exitError{code: ExitUsage, err: errors.New("scan needs at least one domain, e.g. 'seta scan example.com'")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := parseTargets(args)
			if err != nil {
				return &exitError{code: ExitUsage, err: err}
			}

			var checks []core.Check
			for _, c := range a.Registry.All() {
				if c.Meta().Mode == core.Passive {
					checks = append(checks, c)
				}
			}
			jobs := make([]engine.Job, len(targets))
			for i, t := range targets {
				jobs[i] = engine.Job{Target: t, Checks: checks}
			}

			resolver, err := a.setupResolver(cmd.Context(), rf)
			if err != nil {
				return err
			}
			eng := &engine.Engine{Resolver: resolver, Logger: a.logger}
			res := eng.Run(cmd.Context(), jobs)
			return report.Table(cmd.OutOrStdout(), res, report.Options{Color: a.useColor(cmd.OutOrStdout())})
		},
	}
	rf.register(cmd)
	return cmd
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
	if len(targets) == 0 {
		return nil, fmt.Errorf("no domains to scan")
	}
	return targets, nil
}
