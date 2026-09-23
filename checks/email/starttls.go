package email

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/PeacexF/seta/internal/core"
)

// ehloName is a syntactically valid name that identifies the client
// without claiming to be a real mail host.
const ehloName = "seta.invalid"

const smtpTimeout = 45 * time.Second // greeting delays of 10-30s are common

type smtpProbe struct {
	Host     string
	STARTTLS bool
	TLSErr   error // advertised but failed
	Chain    []*x509.Certificate
	Verify   error
	Version  uint16
}

// errConnect marks failures to reach the server, which are check errors:
// port 25 is blocked on most home, cloud and CI networks.
type errConnect struct{ err error }

func (e errConnect) Error() string { return e.err.Error() }
func (e errConnect) Unwrap() error { return e.err }

func probeSMTP(ctx context.Context, env core.Env, host string) (*smtpProbe, error) {
	return core.Memoize(ctx, env.Memo, "smtp:"+host, func(ctx context.Context) (*smtpProbe, error) {
		conn, err := env.Net.Dial(ctx, "tcp", net.JoinHostPort(host, "25"))
		if err != nil {
			return nil, errConnect{fmt.Errorf("connect to %s:25: %w", host, err)}
		}
		defer conn.Close()
		if dl, ok := ctx.Deadline(); ok {
			conn.SetDeadline(dl) //nolint:errcheck
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()

		p := &smtpProbe{Host: host}
		tp := textproto.NewConn(conn)
		if code, msg, err := tp.ReadResponse(220); err != nil {
			if code == 0 {
				return nil, errConnect{fmt.Errorf("%s:25 closed the connection without a greeting", host)}
			}
			return nil, errConnect{fmt.Errorf("%s:25 refused the session: %d %s", host, code, msg)}
		}
		_, ext, err := smtpCmd(tp, 250, "EHLO %s", ehloName)
		if err != nil {
			return nil, fmt.Errorf("%s rejected EHLO: %w", host, err)
		}
		for line := range strings.SplitSeq(ext, "\n") {
			if kw, _, _ := strings.Cut(strings.TrimSpace(line), " "); strings.EqualFold(kw, "STARTTLS") {
				p.STARTTLS = true
			}
		}
		if !p.STARTTLS {
			smtpCmd(tp, 221, "QUIT") //nolint:errcheck
			return p, nil
		}
		if code, msg, err := smtpCmd(tp, 220, "STARTTLS"); err != nil {
			p.TLSErr = fmt.Errorf("STARTTLS answered %d %s", code, msg)
			return p, nil
		}
		// Verification happens below so the chain can be reported either way.
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
		if err := tc.HandshakeContext(ctx); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			p.TLSErr = fmt.Errorf("TLS handshake failed: %w", err)
			return p, nil
		}
		state := tc.ConnectionState()
		p.Chain, p.Version = state.PeerCertificates, state.Version
		p.Verify = verifyChain(env, host, p.Chain)
		smtpCmd(textproto.NewConn(tc), 221, "QUIT") //nolint:errcheck
		return p, nil
	})
}

func smtpCmd(tp *textproto.Conn, expect int, format string, args ...any) (int, string, error) {
	id, err := tp.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	tp.StartResponse(id)
	defer tp.EndResponse(id)
	return tp.ReadResponse(expect)
}

func verifyChain(env core.Env, host string, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("server sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         env.Net.RootCAs(),
		Intermediates: inter,
		CurrentTime:   env.Now(),
	})
	return err
}

// probeAll probes every MX host in parallel. If any host can't be reached
// the whole check errors, so a flaky host never turns into "resolved".
func probeAll(ctx context.Context, env core.Env, t core.Target) ([]*smtpProbe, error) {
	mx, err := loadMX(ctx, env, t.Name)
	if err != nil || !mx.ReceivesMail() {
		return nil, err
	}
	probes := make([]*smtpProbe, len(mx.Hosts))
	errs := make([]error, len(mx.Hosts))
	var wg sync.WaitGroup
	for i, host := range mx.Hosts {
		wg.Go(func() { probes[i], errs[i] = probeSMTP(ctx, env, host) })
	}
	wg.Wait()

	var connectErrs int
	for _, err := range errs {
		var ce errConnect
		if errors.As(err, &ce) {
			connectErrs++
		}
	}
	if connectErrs == len(mx.Hosts) {
		return nil, fmt.Errorf("could not reach any of %s on port 25 (%w); outbound port 25 is blocked on many "+
			"home, cloud and CI networks, so run active mail checks from a server that allows it",
			plural(len(mx.Hosts), "MX host"), errs[0])
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return probes, nil
}

var starttlsMeta = core.Meta{
	Mode:       core.Active,
	Timeout:    smtpTimeout + 5*time.Second,
	References: []string{rfc(3207, ""), rfc(8461, "")},
}

func starttlsCheck(meta core.Meta, judge func(env core.Env, p *smtpProbe) *core.Finding) *check {
	m := starttlsMeta
	m.ID, m.Title, m.Description, m.Remediation, m.Severity = meta.ID, meta.Title, meta.Description, meta.Remediation, meta.Severity
	return define(m, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		ctx, cancel := context.WithTimeout(ctx, smtpTimeout)
		defer cancel()
		probes, err := probeAll(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, p := range probes {
			if f := judge(env, p); f != nil {
				f.Subject = p.Host
				out = append(out, *f)
			}
		}
		return out, nil
	})
}

func certEvidence(env core.Env, p *smtpProbe) map[string]string {
	e := map[string]string{"tls_version": tls.VersionName(p.Version)}
	if len(p.Chain) > 0 {
		leaf := p.Chain[0]
		e["subject"] = leaf.Subject.CommonName
		e["names"] = strings.Join(leaf.DNSNames, ", ")
		e["issuer"] = leaf.Issuer.CommonName
		e["not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	return e
}

var _ = starttlsCheck(core.Meta{
	ID:    "email.starttls.unsupported",
	Title: "MX host does not support STARTTLS",
	Description: "An MX host doesn't advertise STARTTLS, or fails the TLS handshake after advertising " +
		"it. Mail to it travels in plaintext, readable by anyone on the network path.",
	Remediation: "Enable STARTTLS on the mail server with a certificate for its host name.",
	Severity:    core.SeverityHigh,
}, func(env core.Env, p *smtpProbe) *core.Finding {
	switch {
	case !p.STARTTLS:
		return &core.Finding{Evidence: map[string]string{"ehlo": "STARTTLS not advertised"}}
	case p.TLSErr != nil:
		return &core.Finding{
			Title:    "MX host advertises STARTTLS but TLS fails",
			Evidence: map[string]string{"error": p.TLSErr.Error()},
		}
	}
	return nil
})

var _ = starttlsCheck(core.Meta{
	ID:    "email.starttls.cert_invalid",
	Title: "MX host has an invalid TLS certificate",
	Description: "An MX host's certificate is expired, not issued for its host name, or not signed by a " +
		"trusted authority. Senders enforcing MTA-STS or DANE refuse to deliver, and others can't " +
		"tell the real server from an impostor.",
	Remediation: "Install a certificate from a public CA (e.g. Let's Encrypt) covering the MX host name, " +
		"with the full intermediate chain.",
	Severity: core.SeverityMedium,
}, func(env core.Env, p *smtpProbe) *core.Finding {
	if len(p.Chain) == 0 || p.Verify == nil {
		return nil
	}
	e := certEvidence(env, p)
	e["error"] = p.Verify.Error()
	return &core.Finding{Evidence: e}
})

var _ = starttlsCheck(core.Meta{
	ID:    "email.starttls.cert_expiring",
	Title: "MX host TLS certificate expires soon",
	Description: "An MX host's otherwise valid certificate expires within 21 days (7 days: high). " +
		"Renewal automation often covers the web server but not the mail server.",
	Remediation: "Renew the certificate and make sure the mail server reloads it; automate both steps.",
	Severity:    core.SeverityMedium,
}, func(env core.Env, p *smtpProbe) *core.Finding {
	if len(p.Chain) == 0 || p.Verify != nil {
		return nil
	}
	left := p.Chain[0].NotAfter.Sub(env.Now())
	if left > 21*24*time.Hour {
		return nil
	}
	days := int(left.Hours() / 24)
	f := &core.Finding{
		Title:    fmt.Sprintf("MX host TLS certificate expires in %s", plural(days, "day")),
		Evidence: certEvidence(env, p),
	}
	if left <= 7*24*time.Hour {
		f.Severity = core.SeverityHigh
	}
	return f
})
