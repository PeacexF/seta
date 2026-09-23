package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/daemon"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/notify"
	"github.com/PeacexF/seta/internal/state"
	"github.com/PeacexF/seta/internal/version"
)

type daemonFlags struct {
	state     string
	listen    string
	logFormat string
}

// shutdownGrace is how long a run in progress may finish after SIGTERM.
const shutdownGrace = time.Minute

func (a *App) daemonCommand() *cobra.Command {
	var (
		cf configRunFlags
		df daemonFlags
	)
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the config on a schedule and notify about changes",
		Long: "Run the config at start-up and then on its schedule, keep findings in a SQLite\n" +
			"database, and send each notifier a digest of what changed: new, regressed and\n" +
			"resolved findings. Runs that change nothing send nothing.",
		Example: "  seta daemon -c /etc/seta/seta.yaml --state /var/lib/seta/state.db --listen 127.0.0.1:9090",
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runDaemon(cmd, cf, df)
		},
	}
	cf.register(cmd)
	f := cmd.Flags()
	f.StringVar(&df.state, "state", "", "state database (default: state.path from the config)")
	f.StringVar(&df.listen, "listen", "", "serve /healthz on this address, e.g. :9090")
	f.StringVar(&df.logFormat, "log-format", "text", "log format: text or json")
	return cmd
}

func (a *App) runDaemon(cmd *cobra.Command, cf configRunFlags, df daemonFlags) error {
	level := slog.LevelInfo
	if a.debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	switch df.logFormat {
	case "text":
		a.logger = slog.New(slog.NewTextHandler(a.Stderr, opts))
	case "json":
		a.logger = slog.New(slog.NewJSONHandler(a.Stderr, opts))
	default:
		return usageErr("unknown --log-format %q (want text or json)", df.logFormat)
	}
	log := a.logger
	ctx := cmd.Context()

	p, err := a.planConfig(cf)
	if err != nil {
		return err
	}
	cfg := p.cfg
	for _, n := range p.notes {
		log.Warn(n)
	}
	schedule, err := cron.ParseStandard(cfg.Schedule)
	if err != nil {
		return usageErr("invalid schedule: %v", err) // validated while loading
	}
	channels, err := notify.FromConfig(cfg.Notify, notify.Options{UserAgent: version.UserAgent()})
	if err != nil {
		return usageErr("%v", err)
	}
	if len(channels) == 0 {
		log.Warn("no notifiers configured; changes are only logged")
	}
	statePath := orString(df.state, cfg.State.Path)
	store, err := state.Open(ctx, statePath)
	if err != nil {
		return usageErr("%v", err)
	}
	defer store.Close()

	eng, rf, err := a.newEngine(cmd, cf, cfg)
	if err != nil {
		return err
	}

	dispatcher := &notify.Dispatcher{Channels: channels, KV: store, Logger: log, Now: a.now}
	warned := map[int]bool{}
	run := func(ctx context.Context) (daemon.Summary, error) {
		if !rf.skipCheck {
			if err := dnsx.Probe(ctx, eng.Resolver); err != nil {
				return daemon.Summary{}, fmt.Errorf("DNS check failed, so the run was skipped rather than risk false findings: %w", err)
			}
		}
		res := eng.Run(ctx, p.jobs)
		if ctx.Err() != nil {
			return daemon.Summary{}, errors.New("run canceled by shutdown; nothing recorded")
		}
		for _, s := range cfg.Apply(res, a.now()) {
			if !warned[s.Line] {
				warned[s.Line] = true
				log.Warn("suppression expired; its findings are reported again", "check", s.Check, "line", s.Line)
			}
		}
		for _, e := range res.Errors {
			log.Info("check could not complete", "target", e.Target, "check", e.CheckID, "error", e.Err)
		}
		diff, err := store.Record(ctx, res, state.Options{ResolveAfter: cfg.State.ResolveAfter, Canonical: a.canonicalID})
		if err != nil {
			return daemon.Summary{}, fmt.Errorf("record run: %w", err)
		}
		failures := dispatcher.Dispatch(ctx, diff)
		if _, err := store.Prune(ctx, a.now().Add(-time.Duration(cfg.State.Retention))); err != nil {
			log.Warn("pruning old runs failed", "error", err)
		}

		sum := daemon.Summary{RunID: diff.RunID, Started: diff.Started, Duration: diff.Duration, Open: diff.Open, CheckErrors: len(diff.Errors)}
		for _, c := range diff.Changes {
			if c.Suppressed {
				continue
			}
			switch c.Kind {
			case state.New:
				sum.New++
			case state.Regressed:
				sum.Regressed++
			case state.Resolved:
				sum.Resolved++
			}
		}
		for name := range failures {
			sum.NotifyFailures = append(sum.NotifyFailures, name)
		}
		slices.Sort(sum.NotifyFailures)
		log.Info("run finished", "run", sum.RunID, "new", sum.New, "regressed", sum.Regressed, "resolved", sum.Resolved,
			"open", sum.Open, "check_errors", sum.CheckErrors, "duration", sum.Duration.Round(time.Millisecond))
		return sum, nil
	}

	d := &daemon.Daemon{Schedule: schedule, Run: run, Logger: log, Grace: shutdownGrace, Now: a.now}
	if df.listen != "" {
		ln, err := net.Listen("tcp", df.listen)
		if err != nil {
			return usageErr("--listen: %v", err)
		}
		srv := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go srv.Serve(ln)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		}()
		log.Info("serving health checks", "url", "http://"+ln.Addr().String()+"/healthz")
	}

	names := make([]string, len(channels))
	for i, ch := range channels {
		names[i] = ch.Name
	}
	log.Info("seta daemon started", "version", version.Get().Version, "targets", len(p.jobs), "schedule", cfg.Schedule,
		"state", statePath, "notifiers", names)
	err = d.Serve(ctx)
	log.Info("seta daemon stopped")
	return err
}

func orString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
