package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func (a *App) checksCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "Inspect the available checks",
	}
	cmd.AddCommand(a.checksListCommand())
	return cmd
}

func (a *App) checksListCommand() *cobra.Command {
	var module string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available checks",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tMODE\tSEVERITY\tTITLE")
			n := 0
			for _, c := range a.Registry.All() {
				m := c.Meta()
				if module != "" && m.Module != module {
					continue
				}
				n++
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Mode, m.Severity, m.Title)
			}
			if module != "" && n == 0 {
				return &exitError{code: ExitUsage, err: fmt.Errorf("no checks in module %q", module)}
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&module, "module", "", "only list checks from this module (e.g. email)")
	return cmd
}

// noArgs rejects positional arguments with a usage exit code.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return &exitError{code: ExitUsage, err: fmt.Errorf("%s takes no arguments, got %q", cmd.CommandPath(), args)}
	}
	return nil
}
