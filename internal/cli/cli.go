// Package cli implements the seta command-line interface.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/registry"
)

// Exit codes. See the CLI reference for their contract.
const (
	ExitOK          = 0
	ExitFindings    = 1
	ExitUsage       = 2
	ExitCheckErrors = 3
)

// App holds the dependencies of the CLI so tests can substitute them.
type App struct {
	Registry *registry.Registry
	// NewResolver builds a resolver for a list of server specs. Nil means
	// dnsx.NewClient; tests substitute fakes.
	NewResolver func(specs []string) (dnsx.Resolver, error)
	// Prompt asks the user a question and returns the answer line. Nil means
	// asking on the terminal when both Stdin and Stderr are terminals, and
	// treating the session as non-interactive otherwise.
	Prompt func(question string) (string, error)
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Now decides when suppressions expire. Nil means time.Now.
	Now func() time.Time

	// Global flags.
	debug   bool
	noColor bool
	logger  *slog.Logger
	stdin   *bufio.Reader
}

// Run executes the command line in args (without the program name) and
// returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	root := a.rootCommand()
	root.SetArgs(args)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	if ee, ok := errors.AsType[*exitError](err); ok {
		switch _, isConfig := errors.AsType[*config.Errors](ee.err); {
		case isConfig:
			// file:line:col: message, one per line, like a compiler.
			fmt.Fprintln(a.Stderr, ee.err)
		case ee.err != nil:
			fmt.Fprintln(a.Stderr, "seta:", ee.err)
		}
		return ee.code
	}
	fmt.Fprintln(a.Stderr, "seta:", err)
	return ExitUsage
}

// exitError carries a specific exit code out of a command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (a *App) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "seta",
		Short: "Posture monitoring as code for public-facing infrastructure",
		Long: "Seta checks the public posture of your domains (email authentication, TLS, DNS) " +
			"and reports what changed since last time.\n\n" +
			"Only scan domains you own or are authorized to test.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			level := slog.LevelWarn
			if a.debug {
				level = slog.LevelDebug
			}
			a.logger = slog.New(slog.NewTextHandler(a.Stderr, &slog.HandlerOptions{Level: level}))
		},
	}
	root.PersistentFlags().BoolVar(&a.debug, "debug", false, "enable debug logging on stderr")
	root.PersistentFlags().BoolVar(&a.noColor, "no-color", false, "disable colored output")
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &exitError{code: ExitUsage, err: fmt.Errorf("%w (see '%s --help')", err, cmd.CommandPath())}
	})

	root.AddCommand(
		a.versionCommand(),
		a.checksCommand(),
		a.scanCommand(),
		a.runCommand(),
		a.baselineCommand(),
		a.configCommand(),
		a.initCommand(),
	)
	return root
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// useColor reports whether output to w should be colored: only for
// terminals, and never when --no-color or NO_COLOR is set.
func (a *App) useColor(w io.Writer) bool {
	if a.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	return enableVirtualTerminal(f)
}
