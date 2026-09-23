package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/core"
)

func (a *App) configCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Work with the config file",
	}
	cmd.AddCommand(a.configValidateCommand())
	return cmd
}

func (a *App) configValidateCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check a config file for errors without running it",
		Long: "Report every problem in the config with its line number, and warn about expired\n" +
			"suppressions. Exits with code 2 if the config is invalid.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig(cmd.Context(), path)
			if err != nil {
				return err
			}
			runs := 0
			for _, t := range cfg.Targets {
				selected, err := a.Registry.Select(cfg.CheckPatterns(t))
				if err != nil {
					return usageErr("%v", err)
				}
				for _, c := range selected {
					if c.Meta().Mode == core.Passive || cfg.ActiveFor(t) {
						runs++
					}
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is valid: %s, %s per run.\n", cfg.Path,
				plural(len(cfg.Targets), "target"), plural(runs, "check"))
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", config.DefaultPath, "config file")
	return cmd
}
