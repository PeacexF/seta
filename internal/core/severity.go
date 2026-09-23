package core

import "fmt"

// Severity ranks how urgently a finding needs attention.
//
// The zero value is SeverityUnset; checks leave a finding's severity unset to
// inherit the default from their Meta.
type Severity int

const (
	SeverityUnset Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{
	SeverityUnset:    "unset",
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// Severities lists every valid severity from lowest to highest.
func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// Valid reports whether s is one of the defined severities (excluding unset).
func (s Severity) Valid() bool {
	return s >= SeverityInfo && s <= SeverityCritical
}

// ParseSeverity parses a lowercase severity name such as "high".
func ParseSeverity(name string) (Severity, error) {
	for _, s := range Severities() {
		if severityNames[s] == name {
			return s, nil
		}
	}
	return SeverityUnset, fmt.Errorf("unknown severity %q (want one of info, low, medium, high, critical)", name)
}

func (s Severity) MarshalText() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("cannot marshal invalid severity %d", int(s))
	}
	return []byte(s.String()), nil
}

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}
