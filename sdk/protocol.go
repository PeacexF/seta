// Package sdk is the public API for writing Seta exec plugins in Go.
//
// A plugin is an executable named seta-plugin-<name> on $PATH or in the
// config's plugins_dir. Seta talks to it with protocol v1:
//
//	seta-plugin-<name> describe
//	    prints a Describe document to stdout.
//	seta-plugin-<name> run
//	    reads one Request from stdin and prints one Response to stdout.
//
// Each run executes one check against one target. A plugin that exits
// non-zero, prints anything but a single JSON Response, or overruns the
// deadline is reported as a check error, never as a finding. Stderr is
// captured as the plugin's log. Plugins get a minimal environment (PATH,
// HOME, temp and proxy settings) and only their own section of the config,
// never notifier secrets.
//
// The types in this file are the wire format; Plugin implements the
// protocol for Go plugins.
package sdk

import (
	"encoding/json"
	"time"
)

// Protocol is the protocol version this package speaks.
const Protocol = 1

// Env variables Seta sets for plugins, next to the minimal environment.
const (
	EnvProtocol = "SETA_PLUGIN_PROTOCOL"
	EnvVersion  = "SETA_VERSION"
)

type Mode string

const (
	// Passive checks use DNS and other public data only.
	Passive Mode = "passive"
	// Active checks connect to the target's services; Seta runs them only
	// when the user enables active checks for the target.
	Active Mode = "active"
)

type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Describe is the output of `describe`.
type Describe struct {
	Protocol int `json:"protocol"`
	// Name must equal the <name> in the executable's file name.
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Checks  []CheckInfo `json:"checks"`
}

type CheckInfo struct {
	// ID is "<plugin name>.<area>.<condition>" in lowercase letters, digits
	// and underscores. It is permanent: suppressions and state refer to it.
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Remediation is the default fix text for findings that don't set one.
	Remediation string   `json:"remediation,omitempty"`
	Mode        Mode     `json:"mode"`
	Severity    Severity `json:"severity"`
	References  []string `json:"references,omitempty"`
	// Timeout overrides Seta's per-check timeout, as a Go duration ("30s").
	Timeout string `json:"timeout,omitempty"`
}

// Request is the input of `run`.
type Request struct {
	Protocol int    `json:"protocol"`
	Check    string `json:"check"`
	Target   Target `json:"target"`
	// Config is the plugin's section of the config: plugins.<name> merged
	// with the target's own plugins.<name>. It is {} when neither is set.
	Config json.RawMessage `json:"config"`
	// Deadline is when Seta abandons the check and kills the plugin.
	Deadline    time.Time `json:"deadline,omitzero"`
	SetaVersion string    `json:"seta_version,omitempty"`
}

type Target struct {
	// Kind is "domain" in protocol v1.
	Kind string `json:"kind"`
	// Name is lowercase ASCII (punycode) without a trailing dot.
	Name string `json:"name"`
}

// Response is the output of `run`. A non-null Error means the check could
// not reach a verdict (e.g. a lookup failed); Findings are then ignored.
type Response struct {
	Findings []Finding `json:"findings"`
	Error    *string   `json:"error"`
}

// Finding is one problem on the target. Empty fields take the check's
// defaults from Describe.
type Finding struct {
	// Subject is what the finding is about within the target, e.g. a host
	// name. It is part of the finding's identity, so build it
	// deterministically; each finding of a run needs a distinct subject.
	Subject  string   `json:"subject,omitempty"`
	Severity Severity `json:"severity,omitempty"`
	Title    string   `json:"title,omitempty"`
	// Evidence holds raw facts (a record, a date). Changing it does not make
	// a finding new.
	Evidence    map[string]string `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
}
