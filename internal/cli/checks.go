package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/config"
)

func (a *App) checksCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "Inspect the available checks",
	}
	cmd.AddCommand(a.checksListCommand(), a.checksExplainCommand())
	return cmd
}

func (a *App) checksExplainCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:     "explain <check-id>",
		Short:   "Explain what a check verifies, why it matters, and how to fix it",
		Example: "  seta checks explain email.spf.lookup_limit",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return &exitError{code: ExitUsage, err: fmt.Errorf("explain takes one check ID, e.g. 'seta checks explain email.spf.missing'")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			a.loadPluginsFor(cmd.Context(), path, false)
			c, ok := a.Registry.Lookup(args[0])
			if !ok {
				return &exitError{code: ExitUsage, err: fmt.Errorf("unknown check %q; run 'seta checks list' to see all checks", args[0])}
			}
			m := c.Meta()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n%s\n\n", m.ID, m.Title)
			fmt.Fprintf(w, "Module:    %s\nMode:      %s\nSeverity:  %s (default)\n", m.Module, m.Mode, m.Severity)
			if len(m.Aliases) > 0 {
				fmt.Fprintf(w, "Aliases:   %s\n", strings.Join(m.Aliases, ", "))
			}
			fmt.Fprintf(w, "\nWhy it matters\n%s\n", wrap(m.Description, 78))
			fmt.Fprintf(w, "\nHow to fix\n%s\n", wrap(m.Remediation, 78))
			if len(m.References) > 0 {
				fmt.Fprintf(w, "\nReferences\n")
				for _, r := range m.References {
					fmt.Fprintf(w, "  %s\n", r)
				}
			}
			return nil
		},
	}
	pluginsConfigFlag(cmd, &path)
	return cmd
}

// pluginsConfigFlag lets commands that don't run a config still find the
// plugins in its plugins_dir.
func pluginsConfigFlag(cmd *cobra.Command, path *string) {
	cmd.Flags().StringVarP(path, "config", "c", config.DefaultPath, "config whose plugins_dir to search for plugins (ignored if missing)")
}

// wrap breaks text into indented lines of at most width columns.
func wrap(text string, width int) string {
	var lines []string
	line := " "
	for _, word := range strings.Fields(text) {
		if len(line)+1+len(word) > width && line != " " {
			lines = append(lines, line)
			line = " "
		}
		line += " " + word
	}
	return strings.Join(append(lines, line), "\n")
}

func (a *App) checksListCommand() *cobra.Command {
	var module, path string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available checks",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.loadPluginsFor(cmd.Context(), path, false)
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
	pluginsConfigFlag(cmd, &path)
	return cmd
}

// noArgs rejects positional arguments with a usage exit code.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return &exitError{code: ExitUsage, err: fmt.Errorf("%s takes no arguments, got %q", cmd.CommandPath(), args)}
	}
	return nil
}
