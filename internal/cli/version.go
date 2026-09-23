package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/version"
)

func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := version.Get()
			fmt.Fprintf(cmd.OutOrStdout(), "seta %s\n", v.Version)
			if v.Commit != "" {
				commit := v.Commit
				if v.Modified {
					commit += " (modified)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  commit: %s\n", commit)
			}
			if v.Date != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  built:  %s\n", v.Date)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  go:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
