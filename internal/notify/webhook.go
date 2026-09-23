package notify

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/version"
)

// Webhook POSTs a JSON document; with a secret, the body is signed in
// X-Seta-Signature-256 as "sha256=" + hex(HMAC-SHA256(secret, body)).
type Webhook struct {
	URL    string
	Secret string
	HTTP   *HTTP
}

// WebhookSchema is bumped on breaking changes to the payload.
const WebhookSchema = 1

type webhookPayload struct {
	Schema  int             `json:"schema"`
	Event   Event           `json:"event"`
	Tool    map[string]any  `json:"tool"`
	SentAt  time.Time       `json:"sent_at"`
	Run     *webhookRun     `json:"run"`
	Changes []webhookChange `json:"changes"`
}

type webhookRun struct {
	ID           int64     `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	DurationMS   int64     `json:"duration_ms"`
	Targets      []string  `json:"targets"`
	OpenFindings int       `json:"open_findings"`
	CheckErrors  int       `json:"check_errors"`
}

type webhookChange struct {
	Kind        string            `json:"kind"`
	Fingerprint string            `json:"fingerprint"`
	CheckID     string            `json:"check_id"`
	Target      string            `json:"target"`
	Subject     string            `json:"subject"`
	Severity    core.Severity     `json:"severity"`
	Title       string            `json:"title"`
	Evidence    map[string]string `json:"evidence"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
	FirstSeen   time.Time         `json:"first_seen"`
}

func (w *Webhook) Send(ctx context.Context, m *Message) error {
	p := webhookPayload{
		Schema:  WebhookSchema,
		Event:   m.Event,
		Tool:    map[string]any{"name": "seta", "version": version.Get().Version},
		SentAt:  time.Now().UTC(),
		Changes: []webhookChange{},
	}
	if m.Event != EventTest {
		p.Run = &webhookRun{ID: m.RunID, StartedAt: m.Started.UTC(), DurationMS: m.Duration.Milliseconds(),
			Targets: m.Targets, OpenFindings: m.Open, CheckErrors: m.Errors}
		if p.Run.Targets == nil {
			p.Run.Targets = []string{}
		}
	}
	for _, c := range m.Changes {
		f := c.Finding
		wc := webhookChange{Kind: string(c.Kind), Fingerprint: f.Fingerprint(), CheckID: f.CheckID, Target: f.Target,
			Subject: f.Subject, Severity: f.Severity, Title: f.Title, Evidence: f.Evidence, Remediation: f.Remediation,
			References: f.References, FirstSeen: c.FirstSeen.UTC()}
		if wc.Evidence == nil {
			wc.Evidence = map[string]string{}
		}
		if wc.References == nil {
			wc.References = []string{}
		}
		p.Changes = append(p.Changes, wc)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	h := http.Header{}
	h.Set("X-Seta-Event", string(m.Event))
	h.Set("X-Seta-Delivery", deliveryID())
	if w.Secret != "" {
		h.Set("X-Seta-Signature-256", Sign(w.Secret, body))
	}
	_, err = w.HTTP.Post(ctx, w.URL, body, h)
	return err
}

// Sign returns the X-Seta-Signature-256 value for body.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func deliveryID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
