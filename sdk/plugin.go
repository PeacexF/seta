package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Check is one check a Plugin provides.
type Check struct {
	CheckInfo
	// Run returns an error only when it could not reach a verdict. Absence
	// of a problem is an empty result, not an error.
	Run func(ctx context.Context, req *Request) ([]Finding, error)
}

// Plugin implements the protocol for a set of checks:
//
//	func main() {
//		(&sdk.Plugin{Name: "ipv6", Version: "0.1.0", Checks: checks}).Main()
//	}
type Plugin struct {
	Name    string
	Version string
	Checks  []Check
}

// Main serves the command line and exits.
func (p *Plugin) Main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := p.Serve(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// Serve handles one invocation and returns the exit code. Check failures
// are reported in the Response and still exit 0; a non-zero code means
// the plugin itself was misused.
func (p *Plugin) Serve(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: seta-plugin-%s describe|run\n", p.Name)
		return 2
	}
	var out any
	switch args[0] {
	case "describe":
		d := Describe{Protocol: Protocol, Name: p.Name, Version: p.Version, Checks: []CheckInfo{}}
		for _, c := range p.Checks {
			d.Checks = append(d.Checks, c.CheckInfo)
		}
		out = d
	case "run":
		out = p.run(ctx, stdin)
	default:
		fmt.Fprintf(stderr, "unknown command %q (want describe or run)\n", args[0])
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (p *Plugin) run(ctx context.Context, stdin io.Reader) (resp Response) {
	resp.Findings = []Finding{}
	fail := func(err error) Response {
		msg := err.Error()
		return Response{Findings: []Finding{}, Error: &msg}
	}
	var req Request
	if err := json.NewDecoder(stdin).Decode(&req); err != nil {
		return fail(fmt.Errorf("invalid request: %w", err))
	}
	if req.Protocol != Protocol {
		return fail(fmt.Errorf("unsupported protocol %d (this plugin speaks %d)", req.Protocol, Protocol))
	}
	var check *Check
	for i := range p.Checks {
		if p.Checks[i].ID == req.Check {
			check = &p.Checks[i]
		}
	}
	if check == nil {
		return fail(fmt.Errorf("unknown check %q", req.Check))
	}
	if !req.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, req.Deadline)
		defer cancel()
	}
	defer func() {
		if r := recover(); r != nil {
			resp = fail(fmt.Errorf("check panicked: %v", r))
		}
	}()
	findings, err := check.Run(ctx, &req)
	if err != nil {
		return fail(err)
	}
	if findings != nil {
		resp.Findings = findings
	}
	return resp
}

// DecodeConfig unmarshals the plugin's config section into v, rejecting
// settings v doesn't have so typos in seta.yaml surface as check errors.
func (r *Request) DecodeConfig(v any) error {
	if len(r.Config) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(r.Config))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("plugin config: %w", err)
	}
	return nil
}
