package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/state"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// recorder is a fake endpoint. Each request gets the next status from
// statuses (200 once they run out).
type recorder struct {
	mu       sync.Mutex
	statuses []int
	header   http.Header // sent with non-200 replies
	reply    string
	reqs     []*http.Request
	bodies   []string
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.reqs = append(rc.reqs, r)
	rc.bodies = append(rc.bodies, string(body))
	status := 200
	if len(rc.statuses) > 0 {
		status, rc.statuses = rc.statuses[0], rc.statuses[1:]
	}
	if status != 200 {
		for k, v := range rc.header {
			w.Header()[k] = v
		}
	}
	w.WriteHeader(status)
	io.WriteString(w, rc.reply)
}

func serve(t *testing.T, rc *recorder) (*httptest.Server, *HTTP, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(rc)
	t.Cleanup(srv.Close)
	var waits []time.Duration
	h := &HTTP{Client: srv.Client(), UserAgent: "seta-test", Sleep: func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}}
	return srv, h, &waits
}

func change(kind state.Kind, target, check string, sev core.Severity) state.Change {
	return state.Change{Kind: kind, FirstSeen: t0, Finding: core.Finding{
		CheckID: check, Target: target, Severity: sev, Title: "Title of " + check,
		Evidence:    map[string]string{"record": "v=spf1 <include:evil.test> @everyone"},
		Remediation: "Fix it.",
	}}
}

func digest(changes ...state.Change) *Message {
	return &Message{Event: EventDigest, RunID: 7, Started: t0, Duration: time.Second, Targets: []string{"a.test"},
		Changes: changes, Open: 3, Errors: 1, Notifier: "tg"}
}

func TestTelegram(t *testing.T) {
	rc := &recorder{}
	srv, h, _ := serve(t, rc)
	tg := &Telegram{Token: "123:abc", ChatID: "-100", HTTP: h, BaseURL: srv.URL}
	m := digest(change(state.New, "a.test", "email.spf.missing", core.SeverityHigh), change(state.Resolved, "a.test", "email.mx.missing", core.SeverityLow))
	if err := tg.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if rc.reqs[0].URL.Path != "/bot123:abc/sendMessage" {
		t.Errorf("path = %s", rc.reqs[0].URL.Path)
	}
	var body struct {
		ChatID    string `json:"chat_id"`
		Text      string `json:"text"`
		ParseMode string `json:"parse_mode"`
	}
	json.Unmarshal([]byte(rc.bodies[0]), &body)
	want := "<b>Seta</b> · 1 new · 1 resolved\n\n<b>a.test</b>\n" +
		"🔴 <b>NEW</b> · HIGH · Title of email.spf.missing\n<code>email.spf.missing</code>\n" +
		"record: v=spf1 &lt;include:evil.test&gt; @everyone\n<i>Fix:</i> Fix it.\n" +
		"✅ <b>RESOLVED</b> · LOW · Title of email.mx.missing\n<code>email.mx.missing</code>\n" +
		"\n<i>3 open findings · 1 check error · run 7</i>"
	if body.ChatID != "-100" || body.ParseMode != "HTML" || body.Text != want {
		t.Errorf("got %+v\nwant text:\n%s", body, want)
	}
}

func TestTelegramSplitsLongDigests(t *testing.T) {
	var changes []state.Change
	for i := range 60 {
		c := change(state.New, fmt.Sprintf("t%d.test", i/20), fmt.Sprintf("email.spf.c%d", i), core.SeverityHigh)
		c.Finding.Remediation = strings.Repeat("long remediation text ", 20)
		changes = append(changes, c)
	}
	texts := telegramTexts(digest(changes...))
	if len(texts) < 3 {
		t.Fatalf("%d parts", len(texts))
	}
	for i, text := range texts {
		if n := utf16Len(text); n > 4096 {
			t.Errorf("part %d is %d long", i, n)
		}
		if !strings.HasPrefix(text, fmt.Sprintf("<b>Seta</b> · 60 new (%d/%d)\n", i+1, len(texts))) {
			t.Errorf("part %d header: %q", i, text[:60])
		}
		// Every part says which target its first finding belongs to.
		if !strings.HasPrefix(strings.SplitN(text, "\n", 3)[2], "<b>t") {
			t.Errorf("part %d lacks a target heading", i)
		}
		if strings.Count(text, "<b>") != strings.Count(text, "</b>") {
			t.Errorf("part %d has unbalanced tags", i)
		}
	}
	if got := strings.Count(strings.Join(texts, ""), "<code>"); got != 60 {
		t.Errorf("%d findings across parts, want 60", got)
	}
}

func TestDiscord(t *testing.T) {
	rc := &recorder{}
	srv, h, _ := serve(t, rc)
	d := &Discord{URL: srv.URL, HTTP: h}
	if err := d.Send(context.Background(), digest(change(state.Regressed, "a.test", "email.spf.missing", core.SeverityHigh))); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Embeds          []discordEmbed      `json:"embeds"`
		AllowedMentions map[string][]string `json:"allowed_mentions"`
	}
	if err := json.Unmarshal([]byte(rc.bodies[0]), &body); err != nil {
		t.Fatal(err)
	}
	e := body.Embeds[0]
	if e.Title != "Seta · 1 regressed" || e.Color != 0xE67E22 || e.Footer.Text != "3 open findings · 1 check error · run 7" {
		t.Errorf("embed = %+v", e)
	}
	if !strings.Contains(e.Description, "**a.test**") || !strings.Contains(e.Description, "@\u200beveryone") ||
		!strings.Contains(e.Description, `\<include:evil.test\>`) && !strings.Contains(e.Description, `<include:evil.test\>`) {
		t.Errorf("description:\n%s", e.Description)
	}
	if body.AllowedMentions["parse"] == nil || len(body.AllowedMentions["parse"]) != 0 {
		t.Errorf("allowed_mentions = %v", body.AllowedMentions)
	}
}

func TestDiscordLimits(t *testing.T) {
	var changes []state.Change
	for i := range 200 {
		c := change(state.New, "a.test", fmt.Sprintf("email.spf.c%d", i), core.SeverityHigh)
		c.Finding.Remediation = strings.Repeat("x", 250)
		changes = append(changes, c)
	}
	msgs := discordMessages(discordEmbedsFor(digest(changes...)))
	total := 0
	for _, embeds := range msgs {
		size := 0
		for _, e := range embeds {
			if utf16Len(e.Description) > 4096 || utf16Len(e.Title) > 256 {
				t.Errorf("embed over limits: title %d, description %d", utf16Len(e.Title), utf16Len(e.Description))
			}
			size += e.size()
			total += strings.Count(e.Description, "`email.")
		}
		if len(embeds) > 10 || size > 6000 {
			t.Errorf("message with %d embeds, %d characters", len(embeds), size)
		}
	}
	if total != 200 {
		t.Errorf("%d findings delivered, want 200", total)
	}
}

func TestWebhookSignature(t *testing.T) {
	rc := &recorder{}
	srv, h, _ := serve(t, rc)
	w := &Webhook{URL: srv.URL, Secret: "s3cret", HTTP: h}
	if err := w.Send(context.Background(), digest(change(state.New, "a.test", "email.spf.missing", core.SeverityHigh))); err != nil {
		t.Fatal(err)
	}
	r := rc.reqs[0]
	if got, want := r.Header.Get("X-Seta-Signature-256"), Sign("s3cret", []byte(rc.bodies[0])); got != want || !strings.HasPrefix(got, "sha256=") {
		t.Errorf("signature %q, want %q", got, want)
	}
	if r.Header.Get("X-Seta-Event") != "digest" || len(r.Header.Get("X-Seta-Delivery")) != 32 || r.Header.Get("User-Agent") != "seta-test" {
		t.Errorf("headers: %v", r.Header)
	}
	var p struct {
		Schema  int
		Event   string
		Run     struct{ ID int64 }
		Changes []struct {
			Kind, Fingerprint, CheckID string
			Severity                   string
		}
	}
	json.Unmarshal([]byte(rc.bodies[0]), &p)
	if p.Schema != 1 || p.Event != "digest" || p.Run.ID != 7 || len(p.Changes) != 1 || p.Changes[0].Severity != "high" || len(p.Changes[0].Fingerprint) != 32 {
		t.Errorf("payload: %s", rc.bodies[0])
	}

	w.Secret = ""
	w.Send(context.Background(), &Message{Event: EventTest, Notifier: "hook"})
	if rc.reqs[1].Header.Get("X-Seta-Signature-256") != "" || !strings.Contains(rc.bodies[1], `"run":null`) {
		t.Errorf("test message: %v %s", rc.reqs[1].Header, rc.bodies[1])
	}
}

func TestRetries(t *testing.T) {
	ctx := context.Background()
	t.Run("rate limited with Retry-After", func(t *testing.T) {
		rc := &recorder{statuses: []int{429}, header: http.Header{"Retry-After": {"3"}}}
		srv, h, waits := serve(t, rc)
		if _, err := h.Post(ctx, srv.URL, []byte("{}"), nil); err != nil || len(rc.reqs) != 2 || (*waits)[0] != 3*time.Second {
			t.Errorf("err %v, %d requests, waits %v", err, len(rc.reqs), *waits)
		}
	})
	t.Run("rate limited with JSON retry_after", func(t *testing.T) {
		rc := &recorder{statuses: []int{429}, reply: `{"ok":false,"parameters":{"retry_after":7}}`}
		srv, h, waits := serve(t, rc)
		if _, err := h.Post(ctx, srv.URL, []byte("{}"), nil); err != nil || (*waits)[0] != 7*time.Second {
			t.Errorf("err %v, waits %v", err, *waits)
		}
	})
	t.Run("rate limited for too long", func(t *testing.T) {
		rc := &recorder{statuses: []int{429}, header: http.Header{"Retry-After": {"3600"}}}
		srv, h, _ := serve(t, rc)
		if _, err := h.Post(ctx, srv.URL, []byte("{}"), nil); err == nil || !strings.Contains(err.Error(), "rate limited for 1h0m0s") {
			t.Errorf("err %v", err)
		}
	})
	t.Run("server errors back off", func(t *testing.T) {
		rc := &recorder{statuses: []int{500, 502, 503}}
		srv, h, waits := serve(t, rc)
		if _, err := h.Post(ctx, srv.URL, []byte("{}"), nil); err != nil || len(rc.reqs) != 4 {
			t.Fatalf("err %v, %d requests", err, len(rc.reqs))
		}
		for i, w := range *waits {
			if w <= 0 || w > backoffBase<<i {
				t.Errorf("wait %d = %v, want (0, %v]", i, w, backoffBase<<i)
			}
		}
	})
	t.Run("gives up", func(t *testing.T) {
		rc := &recorder{statuses: []int{500, 500, 500, 500, 500, 500}, reply: "upstream down"}
		srv, h, _ := serve(t, rc)
		_, err := h.Post(ctx, srv.URL, []byte("{}"), nil)
		if err == nil || len(rc.reqs) != 5 || !strings.Contains(err.Error(), "gave up after 5 attempts: HTTP 500: upstream down") {
			t.Errorf("err %v, %d requests", err, len(rc.reqs))
		}
	})
	t.Run("client errors are final", func(t *testing.T) {
		rc := &recorder{statuses: []int{401}, reply: `{"description":"Unauthorized"}`}
		srv, h, _ := serve(t, rc)
		var se *StatusError
		if _, err := h.Post(ctx, srv.URL, []byte("{}"), nil); !errors.As(err, &se) || se.Status != 401 || len(rc.reqs) != 1 {
			t.Errorf("err %v, %d requests", err, len(rc.reqs))
		}
	})
}

func TestErrorsHideURLs(t *testing.T) {
	h := &HTTP{Client: &http.Client{Timeout: time.Second}, MaxAttempts: 1}
	tg := &Telegram{Token: "123:secret-token", HTTP: h, BaseURL: "http://127.0.0.1:1"}
	err := tg.Send(context.Background(), digest())
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("err = %v", err)
	}
}

func TestBlockPrivateIPs(t *testing.T) {
	rc := &recorder{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	h := NewHTTP("seta-test", true)
	h.MaxAttempts = 1
	if _, err := h.Post(context.Background(), srv.URL, []byte("{}"), nil); !errors.Is(err, ErrPrivateAddress) || len(rc.reqs) != 0 {
		t.Errorf("err %v, %d requests", err, len(rc.reqs))
	}
	if _, err := NewHTTP("seta-test", false).Post(context.Background(), srv.URL, []byte("{}"), nil); err != nil {
		t.Errorf("unblocked: %v", err)
	}
	for addr, public := range map[string]bool{"8.8.8.8": true, "2606:4700::1": true, "10.0.0.1": false, "100.64.1.1": false,
		"169.254.169.254": false, "::1": false, "fe80::1": false, "::ffff:127.0.0.1": false, "0.0.0.0": false} {
		if got := publicAddr(mustAddr(addr)); got != public {
			t.Errorf("publicAddr(%s) = %v", addr, got)
		}
	}
}

// fakeChannel records messages and fails while failing is set.
type fakeChannel struct {
	mu      sync.Mutex
	msgs    []*Message
	failing error
}

func (f *fakeChannel) Send(_ context.Context, m *Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing != nil {
		return f.failing
	}
	f.msgs = append(f.msgs, m)
	return nil
}

type memKV struct {
	mu sync.Mutex
	m  map[string]string
}

func newKV() *memKV { return &memKV{m: map[string]string{}} }

func (kv *memKV) Get(_ context.Context, k string) (string, bool, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	v, ok := kv.m[k]
	return v, ok, nil
}

func (kv *memKV) Set(_ context.Context, k, v string) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	kv.m[k] = v
	return nil
}

func (kv *memKV) Delete(_ context.Context, k string) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	delete(kv.m, k)
	return nil
}

func rule(minSev core.Severity, heartbeat time.Duration, kinds ...state.Kind) Rule {
	r := Rule{On: map[state.Kind]bool{}, MinSeverity: minSev, Heartbeat: heartbeat}
	for _, k := range kinds {
		r.On[k] = true
	}
	return r
}

func kinds(m *Message) string {
	var s []string
	for _, c := range m.Changes {
		s = append(s, string(c.Kind)+" "+c.Finding.CheckID)
	}
	return strings.Join(s, ", ")
}

func TestDispatch(t *testing.T) {
	ctx := context.Background()
	now := t0
	a, b := &fakeChannel{}, &fakeChannel{failing: errors.New("POST failed for token 123:abcdef")}
	kv := newKV()
	d := &Dispatcher{
		Channels: []Channel{
			{Name: "a", Notifier: a, Rule: rule(core.SeverityMedium, 7*24*time.Hour, DefaultOn...)},
			{Name: "b", Notifier: b, Rule: rule(core.SeverityInfo, 0, state.New), Secrets: []string{"123:abcdef"}},
		},
		KV:  kv,
		Now: func() time.Time { return now },
	}
	suppressed := change(state.New, "a.test", "email.dkim.missing", core.SeverityHigh)
	suppressed.Suppressed = true
	diff := &state.Diff{RunID: 1, Changes: []state.Change{
		change(state.New, "a.test", "email.spf.missing", core.SeverityHigh),
		change(state.New, "a.test", "email.mx.fcrdns", core.SeverityLow),
		change(state.Persisting, "a.test", "email.dmarc.missing", core.SeverityHigh),
		suppressed,
	}}

	failed := d.Dispatch(ctx, diff)
	if len(failed) != 1 || failed["b"] == nil || strings.Contains(failed["b"].Error(), "123:abcdef") || !strings.Contains(failed["b"].Error(), "[redacted]") {
		t.Fatalf("failed = %v", failed)
	}
	if len(a.msgs) != 1 || kinds(a.msgs[0]) != "new email.spf.missing" {
		t.Fatalf("a got %d messages: %v", len(a.msgs), a.msgs)
	}
	if _, ok := kv.m["notify.pending.b"]; !ok {
		t.Fatal("undelivered changes for b not kept")
	}

	// Next run: nothing new for a (silent), b recovers and gets the backlog.
	b.failing = nil
	now = now.Add(time.Hour)
	d.Dispatch(ctx, &state.Diff{RunID: 2, Changes: []state.Change{
		change(state.Persisting, "a.test", "email.spf.missing", core.SeverityHigh),
		change(state.New, "a.test", "email.tlsrpt.missing", core.SeverityLow),
	}})
	if len(a.msgs) != 1 {
		t.Errorf("a should stay silent, got %d messages", len(a.msgs))
	}
	if len(b.msgs) != 1 || kinds(b.msgs[0]) != "new email.spf.missing, new email.mx.fcrdns, new email.tlsrpt.missing" {
		t.Errorf("b got %d messages: %v", len(b.msgs), kinds(b.msgs[len(b.msgs)-1]))
	}
	if _, ok := kv.m["notify.pending.b"]; ok {
		t.Error("pending not cleared after delivery")
	}

	// A week after a's last message, an empty run sends a heartbeat.
	now = t0.Add(7 * 24 * time.Hour)
	d.Dispatch(ctx, &state.Diff{RunID: 3, Targets: []string{"a.test"}, Open: 2})
	if len(a.msgs) != 2 || a.msgs[1].Event != EventHeartbeat || len(b.msgs) != 1 {
		t.Errorf("heartbeat: a %d, b %d messages", len(a.msgs), len(b.msgs))
	}
	d.Dispatch(ctx, &state.Diff{RunID: 4})
	if len(a.msgs) != 2 {
		t.Error("heartbeat repeated too soon")
	}
}

func TestFirstHeartbeat(t *testing.T) {
	a := &fakeChannel{}
	d := &Dispatcher{Channels: []Channel{{Name: "a", Notifier: a, Rule: rule(0, time.Hour, state.New)}}, KV: newKV()}
	d.Dispatch(context.Background(), &state.Diff{RunID: 1})
	if len(a.msgs) != 1 || a.msgs[0].Event != EventHeartbeat {
		t.Errorf("a new channel should confirm it works: %v", a.msgs)
	}
	if got := telegramTexts(a.msgs[0])[0]; got != "<b>Seta</b> · all clear\nNo changes to report. Watching 0 domains; 0 open findings." {
		t.Errorf("heartbeat text %q", got)
	}
}

func TestMergeKeepsUndeliveredNew(t *testing.T) {
	pending := []state.Change{change(state.New, "a.test", "email.spf.missing", core.SeverityHigh), change(state.New, "a.test", "email.mx.fcrdns", core.SeverityLow)}
	current := []state.Change{change(state.Persisting, "a.test", "email.spf.missing", core.SeverityHigh), change(state.Resolved, "a.test", "email.mx.fcrdns", core.SeverityLow)}
	got := merge(pending, current)
	if kinds(&Message{Changes: got}) != "new email.spf.missing, resolved email.mx.fcrdns" {
		t.Errorf("merged: %v", kinds(&Message{Changes: got}))
	}
}

func TestFromConfig(t *testing.T) {
	chs, err := FromConfig([]config.Notifier{
		{Type: "telegram", Name: "tg", BotToken: "1:x", ChatID: "5", Severity: core.SeverityMedium},
		{Type: "discord", Name: "dc", Webhook: "https://discord.com/api/webhooks/1/tok", On: []string{"resolved"}},
	}, Options{UserAgent: "ua"})
	if err != nil {
		t.Fatal(err)
	}
	if !chs[0].Rule.On[state.New] || !chs[0].Rule.On[state.Resolved] || chs[0].Rule.On[state.Persisting] || chs[0].Rule.MinSeverity != core.SeverityMedium {
		t.Errorf("default rule: %+v", chs[0].Rule)
	}
	if chs[1].Rule.On[state.New] || !chs[1].Rule.On[state.Resolved] || chs[1].Secrets[1] != "tok" {
		t.Errorf("discord: %+v", chs[1])
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
