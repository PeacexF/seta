package notify

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/PeacexF/seta/internal/state"
)

// Slack posts Block Kit messages to an incoming webhook.
type Slack struct {
	URL  string
	HTTP *HTTP
}

// Slack limits: 3000 characters per section text and 50 blocks per message.
const (
	slackSection = 2900
	slackBlocks  = 40
)

func (s *Slack) Send(ctx context.Context, m *Message) error {
	for _, body := range slackMessages(m) {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if _, err := s.HTTP.Post(ctx, s.URL, data, nil); err != nil {
			return err
		}
	}
	return nil
}

type slackBlock map[string]any

func mrkdwn(text string) slackBlock {
	return slackBlock{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}}
}

func slackMessages(m *Message) []map[string]any {
	title := "*Seta* · " + slackEscape(headline(m))
	if m.Event != EventDigest {
		return []map[string]any{{"text": "Seta · " + headline(m), "blocks": []slackBlock{mrkdwn(title + "\n" + slackEscape(bodyText(m)))}}}
	}
	var blocks []block
	for _, c := range m.Changes {
		l := kindLabels[c.Kind]
		var b strings.Builder
		b.WriteString(l.emoji + " *" + l.label + "* · " + strings.ToUpper(c.Finding.Severity.String()) + " · " + slackEscape(truncate(c.Finding.Title, 200)))
		if c.Finding.Subject != "" {
			b.WriteString(" (" + slackEscape(truncate(c.Finding.Subject, 100)) + ")")
		}
		b.WriteString("\n`" + c.Finding.CheckID + "`\n")
		if c.Kind == state.New || c.Kind == state.Regressed {
			for _, e := range evidenceLines(c, 2) {
				b.WriteString(slackEscape(e) + "\n")
			}
			if c.Finding.Remediation != "" {
				b.WriteString("_Fix:_ " + slackEscape(truncate(c.Finding.Remediation, 300)) + "\n")
			}
		}
		blocks = append(blocks, block{c.Finding.Target, b.String()})
	}
	heading := func(target string) string { return "\n*" + slackEscape(target) + "*\n" }
	sections := pack(blocks, heading, slackSection, utf8.RuneCountInString)
	footer := slackBlock{"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": slackEscape(footerText(m))}}}

	var parts [][]string
	for i := 0; i < len(sections); i += slackBlocks {
		parts = append(parts, sections[i:min(i+slackBlocks, len(sections))])
	}
	var out []map[string]any
	for i, secs := range parts {
		label := partLabel(i, len(parts))
		bs := []slackBlock{mrkdwn(title + label)}
		for _, s := range secs {
			bs = append(bs, mrkdwn(strings.TrimPrefix(s, "\n")))
		}
		bs = append(bs, footer)
		out = append(out, map[string]any{"text": "Seta · " + headline(m) + label, "blocks": bs})
	}
	return out
}

// slackEscaper keeps finding text from forming links or mentions such as
// <!channel>; Slack's mrkdwn has no escape for * and _.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackEscape(s string) string { return slackEscaper.Replace(s) }
