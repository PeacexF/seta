// Package tlscheck implements the tls checks: certificate validity and
// expiry, and the protocol versions and ciphers a host accepts.
package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PeacexF/seta/checks/internal/checkdef"
	"github.com/PeacexF/seta/checks/internal/web"
	"github.com/PeacexF/seta/internal/core"
)

var set = &checkdef.Set{Module: "tls"}

func Checks() []core.Check       { return set.Checks() }
func Check(id string) core.Check { return set.Check(id) }

// Expiry tiers, as for email.starttls.cert_expiring.
const (
	expiringDays = 21
	urgentDays   = 7
)

// handshakes connects to every TLS host of the target once.
func handshakes(ctx context.Context, env core.Env, t core.Target) ([]*web.Handshake, error) {
	return web.Each(ctx, web.TLSHosts(t), func(h core.Host) (*web.Handshake, error) {
		return web.TLS(ctx, env, h)
	})
}

func certEvidence(c *x509.Certificate) map[string]string {
	return map[string]string{
		"subject":   c.Subject.CommonName,
		"issuer":    c.Issuer.CommonName,
		"not_after": c.NotAfter.UTC().Format(time.RFC3339),
	}
}

func init() {
	set.Define(core.Meta{
		ID:    "tls.cert.invalid",
		Title: "Certificate is not trusted",
		Description: "The host's certificate chain doesn't verify against the public roots: it is expired, " +
			"self-signed, issued by an untrusted CA, or the server doesn't send the intermediate certificates. " +
			"Browsers show a full-page warning, and API clients refuse to connect.",
		Remediation: "Install a certificate from a public CA (e.g. Let's Encrypt) and configure the server to send " +
			"the full chain (leaf plus intermediates). Renew expired certificates and automate renewal.",
		Mode:       core.Passive,
		Severity:   core.SeverityHigh,
		References: []string{"https://www.rfc-editor.org/rfc/rfc5280#section-6"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		hs, err := handshakes(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, h := range hs {
			err := web.Verify(env, h.Chain)
			if err == nil {
				continue
			}
			f := core.Finding{Subject: h.Host.String(), Evidence: map[string]string{"error": err.Error()}}
			if len(h.Chain) > 0 {
				f.Evidence = certEvidence(h.Chain[0])
				f.Evidence["error"] = err.Error()
				if !env.Now().Before(h.Chain[0].NotAfter) {
					f.Severity, f.Title = core.SeverityCritical, "Certificate has expired"
				}
			}
			out = append(out, f)
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "tls.cert.hostname_mismatch",
		Title: "Certificate doesn't cover the host name",
		Description: "The certificate the host presents is not valid for its name, typically because the " +
			"www or apex name is missing from the certificate, or the name is served by a default virtual host.",
		Remediation: "Issue a certificate whose subject alternative names include this host name, " +
			"and make sure the server selects it for this name (SNI).",
		Mode:       core.Passive,
		Severity:   core.SeverityHigh,
		References: []string{"https://www.rfc-editor.org/rfc/rfc6125"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		hs, err := handshakes(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, h := range hs {
			if len(h.Chain) == 0 || h.Chain[0].VerifyHostname(h.Host.Name) == nil {
				continue
			}
			names := h.Chain[0].DNSNames
			if len(names) == 0 {
				names = []string{h.Chain[0].Subject.CommonName}
			}
			out = append(out, core.Finding{Subject: h.Host.String(), Evidence: map[string]string{
				"certificate_names": strings.Join(names, ", "),
			}})
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "tls.cert.expiring",
		Title: "Certificate expires soon",
		Description: fmt.Sprintf("The host's certificate expires within %d days (within %d days: high severity). "+
			"Once it expires, browsers and clients refuse to connect.", expiringDays, urgentDays),
		Remediation: "Renew the certificate, and automate renewal (ACME) so it doesn't depend on someone remembering.",
		Mode:        core.Passive,
		Severity:    core.SeverityMedium,
		References:  []string{"https://www.rfc-editor.org/rfc/rfc8555"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		hs, err := handshakes(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, h := range hs {
			if len(h.Chain) == 0 {
				continue
			}
			left := h.Chain[0].NotAfter.Sub(env.Now())
			// Expired certificates are tls.cert.invalid's finding.
			if left <= 0 || left > expiringDays*24*time.Hour {
				continue
			}
			f := core.Finding{Subject: h.Host.String(), Evidence: certEvidence(h.Chain[0])}
			f.Evidence["days_left"] = strconv.Itoa(int(left.Hours() / 24))
			if left <= urgentDays*24*time.Hour {
				f.Severity = core.SeverityHigh
			}
			out = append(out, f)
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "tls.protocol.no_modern",
		Title: "Host doesn't support TLS 1.2 or later",
		Description: "Offered every version up to TLS 1.3, the host settled for TLS 1.0 or 1.1. Current " +
			"browsers and most HTTP libraries no longer speak these versions and can't connect at all.",
		Remediation: "Enable TLS 1.2 and TLS 1.3 on the server (or upgrade its TLS library).",
		Mode:        core.Passive,
		Severity:    core.SeverityHigh,
		References:  []string{"https://www.rfc-editor.org/rfc/rfc8996"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		hs, err := handshakes(ctx, env, t)
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, h := range hs {
			if h.Version < tls.VersionTLS12 {
				out = append(out, core.Finding{Subject: h.Host.String(), Evidence: map[string]string{"negotiated": tls.VersionName(h.Version)}})
			}
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "tls.protocol.deprecated",
		Title: "Host accepts TLS 1.0 or 1.1",
		Description: "The host still completes handshakes with TLS 1.0 or 1.1, which RFC 8996 deprecated. " +
			"They rely on weak constructions (SHA-1, CBC without AEAD) and fail PCI DSS and most audits. " +
			"Seta can't test SSL 3.0 or older; use testssl.sh for that.",
		Remediation: "Disable TLS 1.0 and 1.1 and keep TLS 1.2 and 1.3, e.g. \"ssl_protocols TLSv1.2 TLSv1.3;\" in nginx.",
		Mode:        core.Active,
		Severity:    core.SeverityMedium,
		References:  []string{"https://www.rfc-editor.org/rfc/rfc8996"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		type accepted struct {
			host     core.Host
			versions []string
		}
		results, err := web.Each(ctx, web.TLSHosts(t), func(h core.Host) (accepted, error) {
			a := accepted{host: h}
			if _, err := web.TLS(ctx, env, h); err != nil {
				return a, err // absent hosts are skipped, and the probes below would only repeat the error
			}
			for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
				ok, err := accepts(ctx, env, h, v, allCiphers())
				if err != nil {
					return a, err
				}
				if ok {
					a.versions = append(a.versions, tls.VersionName(v))
				}
			}
			return a, nil
		})
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, r := range results {
			if len(r.versions) > 0 {
				out = append(out, core.Finding{Subject: r.host.String(), Evidence: map[string]string{"accepted": strings.Join(r.versions, ", ")}})
			}
		}
		return out, nil
	})

	set.Define(core.Meta{
		ID:    "tls.cipher.weak",
		Title: "Host accepts weak cipher suites",
		Description: "The host completes handshakes that offer only cipher suites considered insecure: RC4 or " +
			"3DES (medium severity), or suites without forward secrecy (RSA key exchange) or with CBC-SHA256 " +
			"(low severity). A client that prefers them gets a weak connection, and recorded RSA-key-exchange " +
			"traffic can be decrypted later if the server key leaks. Seta can only offer the weak suites Go " +
			"implements, so NULL and EXPORT suites aren't tested.",
		Remediation: "Restrict the server to AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange; " +
			"the Mozilla SSL Configuration Generator's \"intermediate\" profile is a good baseline.",
		Mode:       core.Active,
		Severity:   core.SeverityMedium,
		References: []string{"https://www.rfc-editor.org/rfc/rfc7525", "https://ssl-config.mozilla.org/"},
	}, func(ctx context.Context, env core.Env, t core.Target) ([]core.Finding, error) {
		type accepted struct {
			host   core.Host
			suites []string
		}
		results, err := web.Each(ctx, web.TLSHosts(t), func(h core.Host) (accepted, error) {
			a := accepted{host: h}
			if _, err := web.TLS(ctx, env, h); err != nil {
				return a, err
			}
			// Offer the remaining weak suites until the server refuses them all.
			var offer []uint16
			for _, s := range tls.InsecureCipherSuites() {
				if !slices.Contains(s.SupportedVersions, tls.VersionTLS13) {
					offer = append(offer, s.ID)
				}
			}
			for len(offer) > 0 {
				state, err := web.Connect(ctx, env, h, &tls.Config{ServerName: h.Name, InsecureSkipVerify: true,
					MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: offer})
				if _, rejected := errors.AsType[*web.HandshakeError](err); rejected {
					break
				} else if err != nil {
					return a, err
				}
				a.suites = append(a.suites, tls.CipherSuiteName(state.CipherSuite))
				offer = slices.DeleteFunc(offer, func(id uint16) bool { return id == state.CipherSuite })
			}
			return a, nil
		})
		if err != nil {
			return nil, err
		}
		var out []core.Finding
		for _, r := range results {
			if len(r.suites) == 0 {
				continue
			}
			slices.Sort(r.suites)
			f := core.Finding{Subject: r.host.String(), Severity: core.SeverityLow, Evidence: map[string]string{"accepted": strings.Join(r.suites, ", ")}}
			for _, s := range r.suites {
				if strings.Contains(s, "RC4") || strings.Contains(s, "3DES") {
					f.Severity = core.SeverityMedium
				}
			}
			out = append(out, f)
		}
		return out, nil
	})
}

// accepts reports whether h completes a handshake at exactly version v.
func accepts(ctx context.Context, env core.Env, h core.Host, v uint16, ciphers []uint16) (bool, error) {
	_, err := web.Connect(ctx, env, h, &tls.Config{ServerName: h.Name, InsecureSkipVerify: true,
		MinVersion: v, MaxVersion: v, CipherSuites: ciphers})
	if _, rejected := errors.AsType[*web.HandshakeError](err); rejected {
		return false, nil
	}
	return err == nil, err
}

// allCiphers offers every suite Go implements, so a server configured only
// for old RSA key exchange still completes an old-version handshake.
func allCiphers() []uint16 {
	var out []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		out = append(out, s.ID)
	}
	return out
}
