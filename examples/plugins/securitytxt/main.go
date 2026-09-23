// Command seta-plugin-securitytxt is an example Seta plugin written with the
// Go SDK. It checks that a domain publishes a current security.txt (RFC
// 9116), which tells researchers how to report vulnerabilities.
//
//	go build -o ~/.local/bin/seta-plugin-securitytxt ./examples/plugins/securitytxt
//	seta scan --active --only 'securitytxt.*' example.com
//
// Settings (seta.yaml):
//
//	plugins:
//	  securitytxt:
//	    warn_days: 30   # also report files expiring within 30 days
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PeacexF/seta/sdk"
)

const version = "0.1.0"

func main() {
	(&sdk.Plugin{Name: "securitytxt", Version: version, Checks: checks}).Main()
}

var rfc9116 = []string{"https://www.rfc-editor.org/rfc/rfc9116"}

var checks = []sdk.Check{
	{
		CheckInfo: sdk.CheckInfo{
			ID:    "securitytxt.file.missing",
			Title: "No security.txt",
			Description: "The domain serves no /.well-known/security.txt, so a researcher who finds a " +
				"vulnerability has no documented way to report it.",
			Remediation: "Publish a text/plain file at https://<domain>/.well-known/security.txt with at least " +
				"Contact and Expires fields; https://securitytxt.org generates one.",
			Mode:       sdk.Active,
			Severity:   sdk.Low,
			References: rfc9116,
		},
		Run: func(ctx context.Context, req *sdk.Request) ([]sdk.Finding, error) {
			f, err := fetch(ctx, req.Target.Name)
			if err != nil || f.fields != nil {
				return nil, err
			}
			return []sdk.Finding{{Evidence: map[string]string{"url": f.url, "response": f.problem}}}, nil
		},
	},
	{
		CheckInfo: sdk.CheckInfo{
			ID:    "securitytxt.file.expired",
			Title: "security.txt is expired or has no expiry",
			Description: "RFC 9116 requires an Expires field so that stale contact details stop being " +
				"trusted. An expired file tells researchers the contacts may no longer work.",
			Remediation: "Review the file's contacts and set Expires to a date less than a year ahead.",
			Mode:        sdk.Active,
			Severity:    sdk.Medium,
			References:  rfc9116,
		},
		Run: func(ctx context.Context, req *sdk.Request) ([]sdk.Finding, error) {
			var cfg struct {
				WarnDays int `json:"warn_days"`
			}
			if err := req.DecodeConfig(&cfg); err != nil {
				return nil, err
			}
			f, err := fetch(ctx, req.Target.Name)
			if err != nil || f.fields == nil {
				return nil, err // a missing file is securitytxt.file.missing's finding
			}
			return expiry(f, time.Now(), cfg.WarnDays), nil
		},
	},
}

func expiry(f *file, now time.Time, warnDays int) []sdk.Finding {
	raw := f.fields["expires"]
	if raw == "" {
		return []sdk.Finding{{Title: "security.txt has no Expires field", Evidence: map[string]string{"url": f.url}}}
	}
	// RFC 3339 allows a lowercase t and z, which time.Parse doesn't.
	exp, err := time.Parse(time.RFC3339, strings.ToUpper(raw))
	if err != nil {
		return []sdk.Finding{{Title: "security.txt has an invalid Expires field", Evidence: map[string]string{"url": f.url, "expires": raw}}}
	}
	switch {
	case !exp.After(now):
		return []sdk.Finding{{Evidence: map[string]string{"url": f.url, "expires": raw}}}
	case exp.Before(now.AddDate(0, 0, warnDays)):
		return []sdk.Finding{{Title: "security.txt expires soon", Severity: sdk.Low, Evidence: map[string]string{"url": f.url, "expires": raw}}}
	}
	return nil
}

type file struct {
	url string
	// fields is nil when there is no usable file; problem says why.
	fields  map[string]string
	problem string
}

var client = &http.Client{}

// baseURL is replaced in tests.
var baseURL = func(domain string) string { return "https://" + domain }

func fetch(ctx context.Context, domain string) (*file, error) {
	f := &file{url: baseURL(domain) + "/.well-known/security.txt"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "seta-plugin-securitytxt/"+version+" (seta/"+os.Getenv(sdk.EnvVersion)+")")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err // unreachable is a check error, not a missing file
	}
	defer resp.Body.Close()
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		f.problem = resp.Status
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", f.url, resp.Status)
	case mediaType != "text/plain":
		// Sites that answer every path with their home page.
		f.problem = fmt.Sprintf("%s with Content-Type %q, not text/plain", resp.Status, mediaType)
	default:
		f.fields = map[string]string{}
		sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if ok && !strings.HasPrefix(k, "#") {
				if k = strings.ToLower(strings.TrimSpace(k)); f.fields[k] == "" {
					f.fields[k] = strings.TrimSpace(v)
				}
			}
		}
		if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
			return nil, err
		}
	}
	return f, nil
}
