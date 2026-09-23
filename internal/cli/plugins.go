package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/plugin"
	"github.com/PeacexF/seta/internal/version"
)

// pluginSet is what loading plugins found; loaded once per process.
type pluginSet struct {
	plugins []*plugin.Plugin
	errs    []error
}

// loadPlugins discovers plugins in dir and $PATH and registers their checks.
// Unusable plugins are warned about on stderr unless quiet.
func (a *App) loadPlugins(ctx context.Context, dir string, quiet bool) *pluginSet {
	if a.plugins != nil {
		return a.plugins
	}
	a.plugins = &pluginSet{}
	if a.noPlugins {
		return a.plugins
	}
	reserved := slices.Clone(plugin.Planned)
	for _, c := range a.Registry.All() {
		reserved = append(reserved, c.Meta().Module)
	}
	opts := plugin.Options{Reserved: reserved, LookupEnv: a.lookupEnv, SetaVersion: version.Get().Version}
	if dir != "" {
		opts.Dirs = []string{dir}
	}
	opts.PATH, _ = a.lookupEnv("PATH")
	plugins, errs := plugin.Load(ctx, opts)
	for _, p := range plugins {
		ok := true
		for _, c := range p.Checks {
			if err := a.Registry.Register(c); err != nil {
				errs = append(errs, &plugin.Error{Name: p.Name, Path: p.Path, Err: err})
				ok = false
				break
			}
		}
		if ok {
			a.plugins.plugins = append(a.plugins.plugins, p)
		}
	}
	a.plugins.errs = errs
	if !quiet {
		for _, err := range errs {
			if _, ok := errors.AsType[*plugin.Error](err); ok {
				fmt.Fprintf(a.Stderr, "warning: %v; its checks are unavailable\n", err)
			} else {
				fmt.Fprintf(a.Stderr, "warning: %v\n", err)
			}
		}
	}
	return a.plugins
}

func (s *pluginSet) names() []string {
	names := []string{}
	for _, p := range s.plugins {
		names = append(names, p.Name)
	}
	return names
}

func (a *App) lookupEnv(key string) (string, bool) {
	if a.LookupEnv != nil {
		return a.LookupEnv(key)
	}
	return os.LookupEnv(key)
}

// loadPluginsFor loads plugins from $PATH and, when the config at path
// exists, its plugins_dir.
func (a *App) loadPluginsFor(ctx context.Context, path string, quiet bool) *pluginSet {
	return a.loadPlugins(ctx, config.PluginsDir(path, a.lookupEnv), quiet)
}

func (a *App) pluginsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Inspect exec plugins",
	}
	cmd.AddCommand(a.pluginsListCommand())
	return cmd
}

func (a *App) pluginsListCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the plugins seta finds and any that can't be used",
		Long: "List the " + plugin.Prefix + "<name> executables found in the config's plugins_dir and\n" +
			"$PATH, the first of each name winning, and explain why any of them can't be used.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.noPlugins {
				return usageErr("plugins are disabled by --no-plugins")
			}
			set := a.loadPluginsFor(cmd.Context(), path, true)
			w := cmd.OutOrStdout()
			if len(set.plugins) == 0 && len(set.errs) == 0 {
				fmt.Fprintf(w, "No plugins found. Plugins are executables named %s<name> in $PATH or plugins_dir.\n", plugin.Prefix)
				return nil
			}
			if len(set.plugins) > 0 {
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tVERSION\tCHECKS\tPATH")
				for _, p := range set.plugins {
					fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", p.Name, orString(p.Version, "-"), len(p.Checks), p.Path)
				}
				if err := tw.Flush(); err != nil {
					return err
				}
				for _, p := range set.plugins {
					if len(p.Shadowed) > 0 {
						fmt.Fprintf(w, "\n%s shadows %s\n", p.Path, strings.Join(p.Shadowed, ", "))
					}
				}
				fmt.Fprintln(w)
			}
			if len(set.errs) > 0 {
				fmt.Fprintf(w, "Problems:\n")
				for _, err := range set.errs {
					fmt.Fprintf(w, "  %v\n", err)
				}
			}
			return nil
		},
	}
	pluginsConfigFlag(cmd, &path)
	return cmd
}
