package notify

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/PeacexF/seta/internal/state"
)

// Discord posts embeds to a channel webhook.
type Discord struct {
	URL  string
	HTTP *HTTP
}

// Discord limits: 4096 characters per embed description, 10 embeds and
// 6000 characters of embed text per message.
const (
	discordDescription = 3800
	discordEmbeds      = 10
	discordMessage     = 5800
)

var discordColors = map[state.Kind]int{
	state.New:        0xE74C3C,
	state.Regressed:  0xE67E22,
	state.Resolved:   0x2ECC71,
	state.Persisting: 0x95A5A6,
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Footer      *discordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (e discordEmbed) size() int {
	n := utf16Len(e.Title) + utf16Len(e.Description)
	if e.Footer != nil {
		n += utf16Len(e.Footer.Text)
	}
	return n
}

func (d *Discord) Send(ctx context.Context, m *Message) error {
	for _, embeds := range discordMessages(discordEmbedsFor(m)) {
		body, err := json.Marshal(map[string]any{
			"username": "Seta",
			"embeds":   embeds,
			// Finding text comes from DNS; never let it ping anyone.
			"allowed_mentions": map[string][]string{"parse": {}},
		})
		if err != nil {
			return err
		}
		if _, err := d.HTTP.Post(ctx, d.URL, body, nil); err != nil {
			return err
		}
	}
	return nil
}

func discordEmbedsFor(m *Message) []discordEmbed {
	title := "Seta · " + headline(m)
	ts := m.Started.UTC().Format("2006-01-02T15:04:05Z")
	if m.Event != EventDigest {
		return []discordEmbed{{Title: title, Description: discordEscape(bodyText(m)), Color: 0x3498DB, Timestamp: ts}}
	}
	color := discordColors[state.Persisting]
	for _, k := range []state.Kind{state.Persisting, state.Resolved, state.Regressed, state.New} {
		for _, c := range m.Changes {
			if c.Kind == k {
				color = discordColors[k]
			}
		}
	}
	var blocks []block
	for _, c := range m.Changes {
		l := kindLabels[c.Kind]
		var b strings.Builder
		b.WriteString(l.emoji + " **" + l.label + "** · " + strings.ToUpper(c.Finding.Severity.String()) + " · " + discordEscape(truncate(c.Finding.Title, 200)))
		if c.Finding.Subject != "" {
			b.WriteString(" (" + discordEscape(truncate(c.Finding.Subject, 100)) + ")")
		}
		b.WriteString("\n`" + c.Finding.CheckID + "`\n")
		if c.Kind == state.New || c.Kind == state.Regressed {
			for _, e := range evidenceLines(c, 2) {
				b.WriteString(discordEscape(e) + "\n")
			}
			if c.Finding.Remediation != "" {
				b.WriteString("*Fix:* " + discordEscape(truncate(c.Finding.Remediation, 300)) + "\n")
			}
		}
		blocks = append(blocks, block{c.Finding.Target, b.String()})
	}
	heading := func(target string) string { return "\n**" + discordEscape(target) + "**\n" }
	parts := pack(blocks, heading, discordDescription, utf16Len)
	footer := &discordFooter{Text: footerText(m)}
	var out []discordEmbed
	for i, p := range parts {
		out = append(out, discordEmbed{Title: title + partLabel(i, len(parts)), Description: strings.TrimPrefix(p, "\n"),
			Color: color, Footer: footer, Timestamp: ts})
	}
	return out
}

// discordMessages groups embeds into messages within Discord's limits.
func discordMessages(embeds []discordEmbed) [][]discordEmbed {
	var out [][]discordEmbed
	var cur []discordEmbed
	size := 0
	for _, e := range embeds {
		if len(cur) > 0 && (len(cur) == discordEmbeds || size+e.size() > discordMessage) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, e)
		size += e.size()
	}
	return append(out, cur)
}

var discordEscaper = strings.NewReplacer(
	`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`, ">", `\>`, "#", `\#`,
	"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "@", "@\u200b",
)

func discordEscape(s string) string { return discordEscaper.Replace(s) }
