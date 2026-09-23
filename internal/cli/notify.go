package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/notify"
	"github.com/PeacexF/seta/internal/version"
)

func (a *App) notifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Work with notifiers",
	}
	cmd.AddCommand(a.notifyTestCommand())
	return cmd
}

func (a *App) notifyTestCommand() *cobra.Command {
	var (
		path  string
		names []string
	)
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Send a test message to each notifier in the config",
		Example: "  seta notify test\n" +
			"  seta notify test --name telegram",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig(path)
			if err != nil {
				return err
			}
			channels, err := notify.FromConfig(cfg.Notify, notify.Options{UserAgent: version.UserAgent()})
			if err != nil {
				return usageErr("%v", err)
			}
			if len(names) > 0 {
				var picked []notify.Channel
				for _, n := range names {
					found := false
					for _, ch := range channels {
						if ch.Name == n {
							picked, found = append(picked, ch), true
						}
					}
					if !found {
						return usageErr("no notifier named %q in %s", n, cfg.Path)
					}
				}
				channels = picked
			}
			if len(channels) == 0 {
				return usageErr("%s has no notifiers; add them under \"notify:\"", cfg.Path)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			failed := notify.Test(ctx, channels)
			w := cmd.OutOrStdout()
			for _, ch := range channels {
				if err := failed[ch.Name]; err != nil {
					fmt.Fprintf(w, "✗ %s: %v\n", ch.Name, err)
				} else {
					fmt.Fprintf(w, "✓ %s\n", ch.Name)
				}
			}
			if len(failed) > 0 {
				return &exitError{code: ExitFindings, err: fmt.Errorf("%s failed", plural(len(failed), "notifier"))}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", config.DefaultPath, "config file")
	cmd.Flags().StringSliceVar(&names, "name", nil, "only test these notifiers")
	return cmd
}
