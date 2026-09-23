package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/state"
)

type slackPayload struct {
	Text   string `json:"text"`
	Blocks []struct {
		Type string `json:"type"`
		Text struct {
			Text string `json:"text"`
		} `json:"text"`
		Elements []struct {
			Text string `json:"text"`
		} `json:"elements"`
	} `json:"blocks"`
}

func TestSlack(t *testing.T) {
	rc := &recorder{}
	srv, h, _ := serve(t, rc)
	s := &Slack{URL: srv.URL, HTTP: h}
	if err := s.Send(context.Background(), digest(change(state.New, "a.test", "email.spf.missing", core.SeverityHigh))); err != nil {
		t.Fatal(err)
	}
	var p slackPayload
	if err := json.Unmarshal([]byte(rc.bodies[0]), &p); err != nil {
		t.Fatal(err)
	}
	if p.Text != "Seta · 1 new" || len(p.Blocks) != 3 || p.Blocks[0].Text.Text != "*Seta* · 1 new" ||
		p.Blocks[2].Type != "context" || p.Blocks[2].Elements[0].Text != "3 open findings · 1 check error · run 7" {
		t.Errorf("payload = %+v", p)
	}
	body := p.Blocks[1].Text.Text
	for _, want := range []string{"*a.test*\n", "🔴 *NEW* · HIGH", "`email.spf.missing`", "&lt;include:evil.test&gt;", "_Fix:_ Fix it."} {
		if !strings.Contains(body, want) {
			t.Errorf("section missing %q:\n%s", want, body)
		}
	}

	if err := s.Send(context.Background(), &Message{Event: EventTest, Notifier: "slack"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rc.bodies[1], `Notifications to \"slack\" work.`) {
		t.Errorf("test message: %s", rc.bodies[1])
	}
}

func TestSlackLimits(t *testing.T) {
	var changes []state.Change
	for i := range 600 {
		c := change(state.New, fmt.Sprintf("t%d.test", i%3), fmt.Sprintf("email.spf.c%d", i), core.SeverityHigh)
		c.Finding.Remediation = strings.Repeat("x", 250)
		changes = append(changes, c)
	}
	msgs := slackMessages(digest(changes...))
	if len(msgs) < 2 {
		t.Fatalf("%d messages, want the digest split", len(msgs))
	}
	total := 0
	for i, m := range msgs {
		blocks := m["blocks"].([]slackBlock)
		if len(blocks) > 50 {
			t.Errorf("message %d has %d blocks", i, len(blocks))
		}
		if want := fmt.Sprintf("(%d/%d)", i+1, len(msgs)); !strings.Contains(m["text"].(string), want) {
			t.Errorf("message %d text %q lacks %s", i, m["text"], want)
		}
		for _, b := range blocks[1 : len(blocks)-1] {
			text := b["text"].(map[string]string)["text"]
			if utf8.RuneCountInString(text) > 3000 {
				t.Errorf("section of %d characters", utf8.RuneCountInString(text))
			}
			total += strings.Count(text, "`email.")
		}
	}
	if total != 600 {
		t.Errorf("%d findings delivered, want 600", total)
	}
}
