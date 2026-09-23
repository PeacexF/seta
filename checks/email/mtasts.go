package email

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/PeacexF/seta/checks/email/internal/mtasts"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/dnsx"
	"github.com/PeacexF/seta/internal/netx"
)

type mtastsInfo struct {
	Records   []string
	RecordErr error
	PolicyURL string
	PolicyErr error // a problem with the policy the domain owner can fix
	Policy    *mtasts.Policy
}

func loadMTASTS(ctx context.Context, env core.Env, domain string) (*mtastsInfo, error) {
	return core.Memoize(ctx, env.Memo, "mtasts:"+domain, func(ctx context.Context) (*mtastsInfo, error) {
		info := &mtastsInfo{}
		var err error
		if info.Records, err = txtRecords(ctx, env, "_mta-sts."+domain, mtasts.IsTXT); err != nil {
			return nil, err
		}
		switch len(info.Records) {
		case 0:
			return info, nil
		case 1:
			if _, err := mtasts.ParseTXT(info.Records[0]); err != nil {
				info.RecordErr = err
				return info, nil
			}
		default:
			info.RecordErr = fmt.Errorf("%d records published; senders ignore all of them", len(info.Records))
			return info, nil
		}
		info.PolicyURL = "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
		body, err := fetchPolicy(ctx, env, info.PolicyURL)
		if err != nil {
			if transient(ctx, err) {
				return nil, fmt.Errorf("fetch %s: %w", info.PolicyURL, err)
			}
			info.PolicyErr = err
			return info, nil
		}
		info.Policy, info.PolicyErr = mtasts.ParsePolicy(body)
		return info, nil
	})
}

func fetchPolicy(ctx context.Context, env core.Env, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := env.Net.HTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return "", fmt.Errorf("HTTP %d redirect to %q; senders must not follow redirects", resp.StatusCode, resp.Header.Get("Location"))
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return "", fmt.Errorf("served as %q; the policy must be text/plain", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mtasts.MaxPolicySize+1))
	if err != nil {
		return "", err
	}
	if len(body) > mtasts.MaxPolicySize {
		return "", fmt.Errorf("policy is larger than %d bytes", mtasts.MaxPolicySize)
	}
	return string(body), nil
}

// transient reports network failures that say nothing about the domain's
// configuration, such as timeouts. DNS, TLS and HTTP-level failures are
// deterministic and count as broken policy hosting.
func transient(ctx context.Context, err error) bool {
	var dnsErr *dnsx.Error
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsErr) {
		return true
	}
	var tlsErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &tlsErr) || errors.As(err, &hostErr) || errors.As(err, &unknownCA) || errors.As(err, &invalid) ||
		errors.Is(err, netx.ErrNoAddress) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

var _ = define(core.Meta{
	ID:    "email.mtasts.missing",
	Title: "No MTA-STS policy",
	Description: "The domain publishes no MTA-STS record at _mta-sts. Without it, senders fall back to " +
		"opportunistic TLS, which an attacker on the network path can strip to read or alter " +
		"mail in transit.",
	Remediation: "Serve a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt (start with " +
		"mode: testing) and publish \"_mta-sts TXT v=STSv1; id=<timestamp>\".",
	Mode:       core.Passive,
	Severity:   core.SeverityLow,
	References: []string{rfc(8461, "")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	info, err := loadMTASTS(ctx, env, t.Name)
	if err != nil || len(info.Records) > 0 {
		return nil, err
	}
	return []core.Finding{{Evidence: map[string]string{"queried": "_mta-sts." + t.Name}}}, nil
})

var _ = define(core.Meta{
	ID:    "email.mtasts.invalid",
	Title: "MTA-STS policy is broken",
	Description: "The domain announces MTA-STS but the record or policy is invalid, the policy can't be " +
		"fetched over valid HTTPS, or the policy doesn't cover every MX host. In enforce mode, senders " +
		"refuse to deliver to MX hosts the policy doesn't list.",
	Remediation: "Serve a valid policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with a " +
		"publicly trusted certificate, list every MX host under mx:, and bump the id= in the TXT record.",
	Mode:       core.Passive,
	Severity:   core.SeverityMedium,
	References: []string{rfc(8461, "3"), rfc(8461, "4.1")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	info, err := loadMTASTS(ctx, env, t.Name)
	if err != nil || len(info.Records) == 0 {
		return nil, err
	}
	switch {
	case info.RecordErr != nil:
		return []core.Finding{{
			Subject:  "record",
			Title:    "MTA-STS TXT record is invalid",
			Evidence: map[string]string{"records": strings.Join(info.Records, " | "), "error": info.RecordErr.Error()},
		}}, nil
	case info.PolicyErr != nil:
		return []core.Finding{{
			Subject:  "policy",
			Title:    "MTA-STS policy is invalid or unreachable",
			Evidence: map[string]string{"url": info.PolicyURL, "error": info.PolicyErr.Error()},
		}}, nil
	case info.Policy.Mode == "none":
		return nil, nil
	}
	var out []core.Finding
	for _, host := range mx.Hosts {
		matched := false
		for _, p := range info.Policy.MX {
			matched = matched || mtasts.Match(p, host)
		}
		if matched {
			continue
		}
		f := core.Finding{
			Subject: "mx:" + host,
			Title:   "MX host " + host + " is not covered by the MTA-STS policy",
			Evidence: map[string]string{
				"policy_mx": strings.Join(info.Policy.MX, ", "),
				"mode":      info.Policy.Mode,
			},
		}
		if info.Policy.Mode == "enforce" {
			f.Severity = core.SeverityHigh
			f.Evidence["effect"] = "senders enforcing MTA-STS will not deliver to this host"
		}
		out = append(out, f)
	}
	return out, nil
})

var _ = define(core.Meta{
	ID:    "email.mtasts.testing",
	Title: "MTA-STS policy is in testing mode",
	Description: "The MTA-STS policy is in mode: testing, so senders report TLS failures but still " +
		"deliver over unprotected connections.",
	Remediation: "Once TLS-RPT reports show no failures, switch the policy to mode: enforce and bump the " +
		"id= in the TXT record.",
	Mode:       core.Passive,
	Severity:   core.SeverityInfo,
	References: []string{rfc(8461, "5")},
}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	info, err := loadMTASTS(ctx, env, t.Name)
	if err != nil || info.Policy == nil || info.Policy.Mode != "testing" {
		return nil, err
	}
	return []core.Finding{{Evidence: map[string]string{"url": info.PolicyURL}}}, nil
})
