package notify

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/checktest"
	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/state"
)

// smtpServer is a fake submission server. replies overrides the reply to
// the Nth MAIL command (0-based) across connections.
type smtpServer struct {
	tls      *tls.Config
	startTLS bool
	replies  map[int]string

	mu    sync.Mutex
	conns int
	mails int
	auth  string
	from  string
	rcpt  []string
	data  string
}

func (s *smtpServer) start(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func (s *smtpServer) serve(conn net.Conn) {
	defer func() { conn.Close() }()
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()
	r := bufio.NewReader(conn)
	say := func(line string) { io.WriteString(conn, line+"\r\n") }
	say("220 localhost ESMTP fake")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		verb := strings.ToUpper(strings.Fields(cmd + " x")[0])
		s.mu.Lock()
		switch verb {
		case "EHLO":
			if s.startTLS && !secure {
				say("250-localhost\r\n250-STARTTLS\r\n250 8BITMIME")
			} else {
				say("250-localhost\r\n250-AUTH PLAIN\r\n250 8BITMIME")
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(conn, s.tls)
			conn, r, secure = tc, bufio.NewReader(tc), true
		case "AUTH":
			creds, _ := base64.StdEncoding.DecodeString(strings.Fields(cmd)[2])
			s.auth = string(creds)
			say("235 ok")
		case "MAIL":
			reply := s.replies[s.mails]
			s.mails++
			if reply != "" {
				say(reply)
				break
			}
			s.from = cmd
			say("250 ok")
		case "RCPT":
			s.rcpt = append(s.rcpt, cmd)
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.data = b.String()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			s.mu.Unlock()
			return
		default:
			say("250 ok")
		}
		s.mu.Unlock()
	}
}

func emailTo(t *testing.T, port int, mode string, ca *checktest.CA) *Email {
	t.Helper()
	from, _ := mail.ParseAddress("Seta <seta@example.com>")
	to, _ := mail.ParseAddress("ops@example.com")
	e := &Email{Host: "localhost", Port: port, TLS: mode, From: from, To: []*mail.Address{to},
		Sleep: func(context.Context, time.Duration) error { return nil }}
	if ca != nil {
		e.TLSConfig = &tls.Config{RootCAs: ca.Pool()}
	}
	return e
}

func TestEmailSTARTTLS(t *testing.T) {
	ca := checktest.NewCA(t)
	cert := ca.Issue(t0.AddDate(-1, 0, 0), time.Now().AddDate(1, 0, 0), "localhost")
	srv := &smtpServer{startTLS: true, tls: &tls.Config{Certificates: []tls.Certificate{cert}}}
	e := emailTo(t, srv.start(t), config.TLSStartTLS, ca)
	e.Username, e.Password = "seta", "pw"

	c := change(state.New, "a.test", "email.spf.missing", core.SeverityHigh)
	c.Finding.Subject = "süb"
	if err := e.Send(context.Background(), digest(c)); err != nil {
		t.Fatal(err)
	}
	if srv.auth != "\x00seta\x00pw" || srv.from != "MAIL FROM:<seta@example.com> BODY=8BITMIME" || len(srv.rcpt) != 1 || srv.rcpt[0] != "RCPT TO:<ops@example.com>" {
		t.Errorf("envelope: auth %q, from %q, rcpt %q", srv.auth, srv.from, srv.rcpt)
	}
	msg, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if subject != "Seta: 1 new on a.test" || msg.Header.Get("From") != `"Seta" <seta@example.com>` ||
		msg.Header.Get("Auto-Submitted") != "auto-generated" || !strings.HasSuffix(msg.Header.Get("Message-ID"), "@example.com>") {
		t.Errorf("headers: %v (subject %q)", msg.Header, subject)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	for _, want := range []string{"Seta · 1 new", "a.test\r\n", "NEW · HIGH · Title of email.spf.missing (süb)",
		"    email.spf.missing\r\n", "record: v=spf1 <include:evil.test> @everyone", "Fix: Fix it.", "3 open findings · 1 check error · run 7"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

func TestEmailRefusesWithoutSTARTTLS(t *testing.T) {
	srv := &smtpServer{}
	e := emailTo(t, srv.start(t), config.TLSStartTLS, nil)
	err := e.Send(context.Background(), &Message{Event: EventTest, Notifier: "mail"})
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") || srv.mails != 0 {
		t.Errorf("err = %v, %d mails", err, srv.mails)
	}
}

func TestEmailImplicitTLS(t *testing.T) {
	ca := checktest.NewCA(t)
	cert := ca.Issue(t0.AddDate(-1, 0, 0), time.Now().AddDate(1, 0, 0), "localhost")
	srv := &smtpServer{}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(conn)
		}
	}()
	e := emailTo(t, ln.Addr().(*net.TCPAddr).Port, config.TLSImplicit, ca)
	e.Username, e.Password = "seta", "pw"
	if err := e.Send(context.Background(), &Message{Event: EventTest, Notifier: "mail"}); err != nil {
		t.Fatal(err)
	}
	if srv.auth != "\x00seta\x00pw" || !strings.Contains(srv.data, `Notifications to "mail" work.`) {
		t.Errorf("auth %q, data:\n%s", srv.auth, srv.data)
	}
}

func TestEmailRetries(t *testing.T) {
	srv := &smtpServer{replies: map[int]string{0: "451 try later"}}
	e := emailTo(t, srv.start(t), config.TLSNone, nil)
	if err := e.Send(context.Background(), &Message{Event: EventTest}); err != nil || srv.conns != 2 || srv.data == "" {
		t.Errorf("temporary failure: %v after %d connections", err, srv.conns)
	}

	srv = &smtpServer{replies: map[int]string{0: "550 no such sender"}}
	e = emailTo(t, srv.start(t), config.TLSNone, nil)
	if err := e.Send(context.Background(), &Message{Event: EventTest}); err == nil || !strings.Contains(err.Error(), "550") || !strings.Contains(err.Error(), "no such sender") || srv.conns != 1 {
		t.Errorf("permanent failure: %v after %d connections", err, srv.conns)
	}
}

func TestEmailFromConfig(t *testing.T) {
	chs, err := FromConfig([]config.Notifier{{Type: "email", Name: "mail", Host: "smtp.example.com", Port: 587, TLS: config.TLSStartTLS,
		Username: "u", Password: "hunter22", From: "seta@example.com", To: []string{"a@example.com", "B <b@example.com>"}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := chs[0].Notifier.(*Email)
	if e.From.Address != "seta@example.com" || len(e.To) != 2 || e.To[1].Name != "B" || chs[0].Secrets[0] != "hunter22" {
		t.Errorf("email = %+v, secrets %v", e, chs[0].Secrets)
	}
	if _, err := FromConfig([]config.Notifier{{Type: "email", From: "x", To: []string{"a@b.c"}}}, Options{}); err == nil {
		t.Error("invalid from accepted")
	}
}
