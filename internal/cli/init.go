package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PeacexF/seta/internal/baseline"
	"github.com/PeacexF/seta/internal/config"
)

type initTarget struct {
	domain    string
	selectors []string
}

func (a *App) initCommand() *cobra.Command {
	var (
		domains []string
		output  string
		active  bool
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a starter config file",
		Long: "Write a commented seta.yaml for your domains. In a terminal, init asks for the domains\n" +
			"and their DKIM selectors; elsewhere, pass them with --domain.",
		Example: "  seta init\n" +
			"  seta init --domain example.com --domain example.org",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(output); err == nil && !force {
				return usageErr("%s already exists; pass --force to overwrite it", output)
			}
			var targets []initTarget
			if len(domains) > 0 {
				parsed, err := parseTargets(domains)
				if err != nil {
					return usageErr("%v", err)
				}
				for _, t := range parsed {
					targets = append(targets, initTarget{domain: t.Name})
				}
			} else {
				var err error
				if targets, active, err = a.askInit(); err != nil {
					return err
				}
			}

			data := renderInit(targets, active)
			if _, err := config.Parse(output, data, config.Options{Registry: a.Registry}); err != nil {
				if errs, ok := errors.AsType[*config.Errors](err); ok {
					return usageErr("%s", errs.List[0].Msg)
				}
				return err
			}
			if err := os.WriteFile(output, data, 0o644); err != nil {
				return usageErr("%v", err)
			}
			fmt.Fprintf(a.Stderr, "Wrote %s for %s. Next:\n"+
				"  seta config validate    check the file after editing it\n"+
				"  seta run                run the checks\n"+
				"  seta baseline           accept today's findings, so CI fails only on new ones\n",
				output, plural(len(targets), "domain"))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&domains, "domain", nil, "domain to monitor (repeatable); skips the questions")
	f.BoolVar(&active, "active", false, "enable active checks, which connect to the domains' mail servers")
	f.StringVarP(&output, "output", "o", config.DefaultPath, "file to write")
	f.BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}

func (a *App) askInit() ([]initTarget, bool, error) {
	line, asked, err := a.prompt("Domains to monitor (e.g. example.com example.org): ")
	if err != nil {
		return nil, false, usageErr("%v", err)
	}
	if !asked {
		return nil, false, usageErr("pass --domain, or run 'seta init' in a terminal to answer questions")
	}
	parsed, err := parseTargets(splitList(line))
	if err != nil {
		return nil, false, usageErr("%v", err)
	}
	if len(parsed) == 0 {
		return nil, false, usageErr("no domains given")
	}
	var targets []initTarget
	for _, t := range parsed {
		line, _, err := a.prompt(fmt.Sprintf("DKIM selectors for %s (the s= tag of its DKIM-Signature headers; Enter to skip): ", t.Name))
		if err != nil {
			return nil, false, usageErr("%v", err)
		}
		targets = append(targets, initTarget{domain: t.Name, selectors: splitList(line)})
	}
	active, _, err := a.confirm("Run active checks (they connect to your mail servers on port 25)? [y/N] ", false)
	if err != nil {
		return nil, false, usageErr("%v", err)
	}
	return targets, active, nil
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

func renderInit(targets []initTarget, active bool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# yaml-language-server: $schema=%s\n", config.SchemaURL)
	b.WriteString(`# Seta config. Check it with 'seta config validate'.
# Values can use environment variables: ${VAR}.
version: 1

# DNS servers: system (default), doh, dot, or addresses like 1.1.1.1 and tls://1.1.1.1.
# resolver:
#   servers: [doh]

defaults:
  checks: ["email.*"]
  # Active checks connect to your servers (STARTTLS on port 25).
`)
	fmt.Fprintf(&b, "  active: %t\n\ntargets:\n", active)
	for _, t := range targets {
		fmt.Fprintf(&b, "  - domain: %s\n    email:\n", t.domain)
		if len(t.selectors) > 0 {
			fmt.Fprintf(&b, "      dkim_selectors: %s\n", yamlList(t.selectors))
		} else {
			b.WriteString("      # The s= tag of your DKIM-Signature headers; without it Seta guesses common names.\n" +
				"      # dkim_selectors: [google]\n")
		}
		b.WriteString("      # MX hosts you expect; any difference is reported.\n" +
			"      # expected_mx: [mx1.example.net, mx2.example.net]\n")
	}
	example := "example.com"
	if len(targets) > 0 {
		example = targets[0].domain
	}
	fmt.Fprintf(&b, `
# Report a check's findings at another severity.
# severity_overrides:
#   email.dmarc.policy_none: low

# Accept findings you can't fix yet. Each needs a reason; once expired, the
# findings are reported again. For CI, see 'seta baseline' (%s).
# suppressions:
#   - check: email.mtasts.missing
#     target: %s
#     reason: "Receives no mail"
#     expires: 2027-01-01
`, baseline.DefaultPath, example)
	return []byte(b.String())
}

// yamlList renders a flow sequence. JSON strings are valid YAML scalars, so
// this quotes safely whatever the values contain.
func yamlList(items []string) string {
	data, _ := json.Marshal(items)
	return strings.ReplaceAll(string(data), `","`, `", "`)
}
