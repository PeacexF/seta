package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/version"
)

// resolverFlags are shared by every command that queries DNS.
type resolverFlags struct {
	specs     []string
	skipCheck bool
}

func (rf *resolverFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&rf.specs, "resolver", []string{"system"},
		"DNS servers: 'system', 'doh' (DNS over HTTPS), 'dot' (DNS over TLS), or a list of\n"+
			"IP[:port], tls://host[:port] and https://host/path servers")
	cmd.Flags().BoolVar(&rf.skipCheck, "skip-dns-check", false,
		"don't verify that the resolver answers correctly before scanning")
}

// encryptedChoices are offered, in order, when the configured resolver fails
// the check.
var encryptedChoices = []struct{ preset, label string }{
	{"doh", "DNS over HTTPS"},
	{"dot", "DNS over TLS"},
}

// setupResolver builds the resolver the flags ask for and verifies it with
// dnsx.Probe. A resolver that fails would turn existing records into false
// "missing" findings, so Seta never scans through one silently: it reports
// the problem and, when a person is at the terminal, offers to continue over
// encrypted DNS instead.
func (a *App) setupResolver(ctx context.Context, rf resolverFlags) (dnsx.Resolver, error) {
	specs, err := a.expandResolverSpecs(rf.specs)
	if err != nil {
		return nil, &exitError{code: ExitUsage, err: err}
	}
	r, err := a.buildResolver(specs)
	if err != nil {
		return nil, &exitError{code: ExitUsage, err: err}
	}
	if rf.skipCheck {
		return r, nil
	}

	perr := dnsx.Probe(ctx, r)
	if perr == nil {
		return r, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	a.reportProbeFailure(specs, perr)

	if allEncrypted(specs) {
		return nil, &exitError{code: ExitUsage, err: errors.New("cannot scan without a working resolver")}
	}
	ok, asked, err := a.ask("Continue using encrypted DNS (DNS over HTTPS via 1.1.1.1 and 9.9.9.9)? [Y/n] ")
	if err != nil {
		return nil, &exitError{code: ExitUsage, err: err}
	}
	if !asked {
		return nil, &exitError{code: ExitUsage, err: errors.New("refusing to scan through an unreliable resolver; " +
			"re-run with --resolver doh (DNS over HTTPS) or --resolver dot (DNS over TLS), or pass --skip-dns-check to scan anyway")}
	}
	if !ok {
		return nil, &exitError{code: ExitUsage, err: errors.New("scan aborted")}
	}

	for _, choice := range encryptedChoices {
		servers := dnsx.Presets[choice.preset]
		r, err := a.buildResolver(servers)
		if err != nil {
			return nil, &exitError{code: ExitUsage, err: err}
		}
		if err := dnsx.Probe(ctx, r); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			fmt.Fprintf(a.Stderr, "%s did not work either: %v\n", choice.label, err)
			continue
		}
		fmt.Fprintf(a.Stderr, "Using %s (%s). To skip this question next time, pass --resolver %s.\n\n",
			choice.label, strings.Join(servers, ", "), choice.preset)
		return r, nil
	}
	return nil, &exitError{code: ExitUsage, err: errors.New("no working resolver: encrypted DNS failed the check as well")}
}

// expandResolverSpecs replaces "system" and preset names with server specs.
func (a *App) expandResolverSpecs(values []string) ([]string, error) {
	var specs []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		switch {
		case v == "system":
			servers, err := dnsx.SystemServers()
			if err != nil {
				a.logger.Warn("using fallback DNS servers", "reason", err, "servers", dnsx.FallbackServers)
				servers = dnsx.FallbackServers
			}
			specs = append(specs, servers...)
		case dnsx.Presets[v] != nil:
			specs = append(specs, dnsx.Presets[v]...)
		case v == "":
			return nil, errors.New("empty --resolver value")
		default:
			specs = append(specs, v)
		}
	}
	return specs, nil
}

func (a *App) buildResolver(specs []string) (dnsx.Resolver, error) {
	if a.NewResolver != nil {
		return a.NewResolver(specs)
	}
	return dnsx.NewClient(specs, dnsx.Options{UserAgent: version.UserAgent()})
}

func allEncrypted(specs []string) bool {
	for _, s := range specs {
		srv, err := dnsx.ParseServer(s)
		if err != nil || !srv.Transport.Encrypted() {
			return false
		}
	}
	return true
}

func (a *App) reportProbeFailure(specs []string, err error) {
	var pe *dnsx.ProbeError
	if !errors.As(err, &pe) {
		fmt.Fprintf(a.Stderr, "DNS check failed: %v\n\n", err)
		return
	}
	state := "is not answering correctly"
	if pe.Tampered {
		state = "is returning incomplete answers"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "DNS check failed: the resolver (%s) %s:\n", strings.Join(specs, ", "), state)
	for _, p := range pe.Problems {
		fmt.Fprintf(&b, "  - %s\n", p)
	}
	if pe.Tampered {
		b.WriteString("Something on this network is probably intercepting or filtering DNS. Scanning through it\n" +
			"would report records that exist as missing.\n\n")
	} else {
		b.WriteString("Check your network connection and DNS settings.\n\n")
	}
	fmt.Fprint(a.Stderr, b.String())
}

// ask poses a yes/no question on stderr. asked is false when nobody is there
// to answer (not a terminal, or a CI job), in which case callers must not
// assume either answer. An empty answer means yes.
func (a *App) ask(question string) (yes, asked bool, err error) {
	if a.Prompt != nil {
		yes, err = a.Prompt(question)
		return yes, true, err
	}
	in, inOK := a.Stdin.(*os.File)
	errOut, outOK := a.Stderr.(*os.File)
	if !inOK || !outOK || !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(errOut.Fd())) {
		return false, false, nil
	}
	fmt.Fprint(a.Stderr, question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, true, nil // EOF (Ctrl-D) counts as no
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, true, nil
	}
	return false, true, nil
}
