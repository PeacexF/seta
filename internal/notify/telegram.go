package notify

import (
	"context"
	"encoding/json"
	"html"
	"strings"

	"github.com/PeacexF/seta/internal/state"
)

// Telegram sends HTML messages through the Bot API.
type Telegram struct {
	Token  string
	ChatID string
	HTTP   *HTTP
	// BaseURL defaults to https://api.telegram.org.
	BaseURL string
}

// telegramLimit stays under the 4096-character message limit; raw HTML is
// never shorter than the text Telegram counts after parsing it.
const telegramLimit = 4000

func (t *Telegram) Send(ctx context.Context, m *Message) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	for _, text := range telegramTexts(m) {
		body, err := json.Marshal(map[string]any{
			"chat_id":              t.ChatID,
			"text":                 text,
			"parse_mode":           "HTML",
			"link_preview_options": map[string]bool{"is_disabled": true},
		})
		if err != nil {
			return err
		}
		if _, err := t.HTTP.Post(ctx, base+"/bot"+t.Token+"/sendMessage", body, nil); err != nil {
			return err
		}
	}
	return nil
}

func telegramTexts(m *Message) []string {
	esc := html.EscapeString
	header := "<b>Seta</b> · " + esc(headline(m))
	if m.Event != EventDigest {
		return []string{header + "\n" + esc(bodyText(m))}
	}
	var blocks []block
	for _, c := range m.Changes {
		l := kindLabels[c.Kind]
		var b strings.Builder
		b.WriteString(l.emoji + " <b>" + l.label + "</b> · " + strings.ToUpper(c.Finding.Severity.String()) + " · " + esc(truncate(c.Finding.Title, 200)))
		if c.Finding.Subject != "" {
			b.WriteString(" (" + esc(truncate(c.Finding.Subject, 100)) + ")")
		}
		b.WriteString("\n<code>" + esc(c.Finding.CheckID) + "</code>\n")
		if c.Kind == state.New || c.Kind == state.Regressed {
			for _, e := range evidenceLines(c, 2) {
				b.WriteString(esc(e) + "\n")
			}
			if c.Finding.Remediation != "" {
				b.WriteString("<i>Fix:</i> " + esc(truncate(c.Finding.Remediation, 300)) + "\n")
			}
		}
		blocks = append(blocks, block{c.Finding.Target, b.String()})
	}
	heading := func(target string) string { return "\n<b>" + esc(target) + "</b>\n" }
	footer := "\n<i>" + esc(footerText(m)) + "</i>"
	chunks := pack(blocks, heading, telegramLimit-utf16Len(header+footer)-partReserve, utf16Len)
	for i, c := range chunks {
		chunks[i] = header + partLabel(i, len(chunks)) + "\n" + c + footer
	}
	return chunks
}
