// Package baseline reads and writes baseline files: findings accepted as
// known, so that CI fails only on new ones.
package baseline

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/engine"
)

// Version is bumped on breaking changes to the file format.
const Version = 1

const DefaultPath = ".seta-baseline.json"

// File is meant to be committed and reviewed, so it has no timestamps and
// its entries are sorted: regenerating it only changes what changed.
type File struct {
	Version  int     `json:"version"`
	Findings []Entry `json:"findings"`
}

// Entry identifies a finding by check ID, target and subject. Severity and
// title are there for reviewers; changing them doesn't affect matching.
type Entry struct {
	Fingerprint string        `json:"fingerprint"`
	CheckID     string        `json:"check_id"`
	Target      string        `json:"target"`
	Subject     string        `json:"subject,omitempty"`
	Severity    core.Severity `json:"severity"`
	Title       string        `json:"title"`
}

func New(findings []core.Finding) *File {
	f := &File{Version: Version, Findings: []Entry{}}
	for _, x := range findings {
		f.Findings = append(f.Findings, Entry{
			Fingerprint: x.Fingerprint(),
			CheckID:     x.CheckID,
			Target:      x.Target,
			Subject:     x.Subject,
			Severity:    x.Severity,
			Title:       x.Title,
		})
	}
	slices.SortFunc(f.Findings, func(a, b Entry) int {
		return cmp.Or(strings.Compare(a.Target, b.Target), strings.Compare(a.CheckID, b.CheckID), strings.Compare(a.Subject, b.Subject))
	})
	return f
}

func (f *File) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(f)
}

func Read(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("baseline %s: unsupported version %d (this version of seta reads version %d)", path, f.Version, Version)
	}
	for i, e := range f.Findings {
		if e.CheckID == "" || e.Target == "" {
			return nil, fmt.Errorf("baseline %s: finding %d lacks check_id or target", path, i+1)
		}
	}
	return &f, nil
}

// Apply moves findings listed in the baseline from res.Findings to
// res.Baselined. canonical maps a check ID recorded in the baseline to its
// current ID, so baselines survive check renames. It returns the number of
// baseline entries that no longer occur (fixed, or their check didn't run).
func (f *File) Apply(res *engine.Result, canonical func(id string) string) (gone int) {
	known := make(map[string]bool, len(f.Findings))
	for _, e := range f.Findings {
		known[core.Fingerprint(canonical(e.CheckID), e.Target, e.Subject)] = true
	}
	seen := make(map[string]bool)
	kept := res.Findings[:0]
	for _, x := range res.Findings {
		fp := x.Fingerprint()
		if known[fp] {
			seen[fp] = true
			res.Baselined = append(res.Baselined, x)
			continue
		}
		kept = append(kept, x)
	}
	res.Findings = kept
	return len(known) - len(seen)
}
