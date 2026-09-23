package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/state"
)

// Email sends a plain-text digest over SMTP.
type Email struct {
	Host string
	Port int
	// TLS is config.TLSStartTLS, TLSImplicit or TLSNone.
	TLS                string
	Username, Password string
	From               *mail.Address
	To                 []*mail.Address
	// TLSConfig replaces the default (verify against system roots) in tests.
	TLSConfig *tls.Config
	// Sleep waits between attempts; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

const emailAttempts = 3

func (e *Email) Send(ctx context.Context, m *Message) error {
	msg := e.message(m, time.Now())
	var err error
	for attempt := range emailAttempts {
		if attempt > 0 {
			if serr := (&HTTP{Sleep: e.Sleep}).sleep(ctx, backoff(attempt)); serr != nil {
				return errors.Join(err, serr)
			}
		}
		if err = e.send(ctx, msg); err == nil || permanent(err) || ctx.Err() != nil {
			return err
		}
	}
	return fmt.Errorf("gave up after %d attempts: %w", emailAttempts, err)
}

// permanent reports 5xx replies, which retrying won't change.
func permanent(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && te.Code >= 500
}

func (e *Email) send(ctx context.Context, msg []byte) error {
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(time.Minute))

	cfg := e.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg = cfg.Clone()
	cfg.ServerName = e.Host
	if e.TLS == config.TLSImplicit {
		conn = tls.Client(conn, cfg)
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if e.TLS == config.TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%s does not offer STARTTLS; set tls: tls for port 465, or tls: none for a trusted local relay", addr)
		}
		if err := c.StartTLS(cfg); err != nil {
			return err
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.From.Address); err != nil {
		return err
	}
	for _, to := range e.To {
		if err := c.Rcpt(to.Address); err != nil {
			return fmt.Errorf("recipient %s: %w", to.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (e *Email) message(m *Message, now time.Time) []byte {
	subject := "Seta: " + headline(m)
	targets := map[string]bool{}
	for _, c := range m.Changes {
		targets[c.Finding.Target] = true
	}
	if len(targets) == 1 {
		subject += " on " + m.Changes[0].Finding.Target
	}
	to := make([]string, len(e.To))
	for i, a := range e.To {
		to[i] = a.String()
	}
	id := make([]byte, 12)
	rand.Read(id)
	_, domain, _ := strings.Cut(e.From.Address, "@")

	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", e.From.String())
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	// Keeps vacation responders from replying.
	header("Auto-Submitted", "auto-generated")
	header("X-Seta-Event", string(m.Event))
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	qp.Write([]byte(strings.ReplaceAll(emailText(m), "\n", "\r\n")))
	qp.Close()
	return b.Bytes()
}

func emailText(m *Message) string {
	var b strings.Builder
	b.WriteString("Seta · " + headline(m) + "\n")
	if m.Event != EventDigest {
		b.WriteString("\n" + bodyText(m) + "\n")
		return b.String()
	}
	group := ""
	for _, c := range m.Changes {
		f := c.Finding
		if f.Target != group {
			group = f.Target
			b.WriteString("\n" + group + "\n")
		}
		l := kindLabels[c.Kind]
		b.WriteString("\n  " + l.label + " · " + strings.ToUpper(f.Severity.String()) + " · " + f.Title)
		if f.Subject != "" {
			b.WriteString(" (" + f.Subject + ")")
		}
		b.WriteString("\n    " + f.CheckID + "\n")
		if c.Kind == state.New || c.Kind == state.Regressed {
			for _, e := range evidenceLines(c, 5) {
				b.WriteString("    " + e + "\n")
			}
			if f.Remediation != "" {
				b.WriteString("    Fix: " + f.Remediation + "\n")
			}
		}
	}
	b.WriteString("\n-- \n" + footerText(m) + "\n")
	return b.String()
}
