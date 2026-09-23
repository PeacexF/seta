// Package version reports the build's version, set at link time by
// goreleaser and otherwise read from the Go build info.
package version

import (
	"runtime/debug"
	"sync"
)

// Set with -ldflags "-X github.com/PeacexF/seta/internal/version.Version=...".
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Info describes the running binary.
type Info struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	Modified  bool
}

var get = sync.OnceValue(func() Info {
	info := Info{Version: Version, Commit: Commit, Date: Date}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.GoVersion = bi.GoVersion
		// `go install ...@v0.1.0` records the module version.
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
})

// Get returns the version information for this binary.
func Get() Info { return get() }

// UserAgent identifies Seta to the services it talks to, e.g. "seta/v0.1.0".
func UserAgent() string { return "seta/" + Get().Version }
