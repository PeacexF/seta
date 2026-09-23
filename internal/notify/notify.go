// Package notify delivers run digests to Telegram, Discord and webhooks.
package notify

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PeacexF/seta/internal/config"
	"github.com/PeacexF/seta/internal/core"
	"github.com/PeacexF/seta/internal/state"
)

type Event string

const (
	EventDigest    Event = "digest"
	EventHeartbeat Event = "heartbeat"
	EventTest      Event = "test"
)

// Message is what a notifier renders: a digest of changes, an all-clear
// heartbeat, or a test.
type Message struct {
	Event    Event
	RunID    int64
	Started  time.Time
	Duration time.Duration
	Targets  []string
	Changes  []state.Change
	Open     int
	Errors   int
	// Notifier is the name of the channel the message goes to.
	Notifier string
}

type Notifier interface {
	Send(ctx context.Context, m *Message) error
}

// Rule selects which changes a channel receives.
type Rule struct {
	On          map[state.Kind]bool
	MinSeverity core.Severity
	Heartbeat   time.Duration
}

var DefaultOn = []state.Kind{state.New, state.Regressed, state.Resolved}

func (r Rule) Filter(changes []state.Change) []state.Change {
	var out []state.Change
	for _, c := range changes {
		if !c.Suppressed && r.On[c.Kind] && c.Finding.Severity >= r.MinSeverity {
			out = append(out, c)
		}
	}
	return out
}

type Channel struct {
	Name     string
	Notifier Notifier
	Rule     Rule
	// Secrets are replaced in error messages before they are logged.
	Secrets []string
}

type Options struct {
	UserAgent string
	// HTTP replaces the transport in tests.
	HTTP *HTTP
}

// FromConfig builds the channels declared in the config.
func FromConfig(nts []config.Notifier, opts Options) ([]Channel, error) {
	var out []Channel
	for _, nt := range nts {
		h := opts.HTTP
		if h == nil {
			h = NewHTTP(opts.UserAgent, nt.BlockPrivateIPs)
		}
		ch := Channel{Name: nt.Name, Rule: Rule{MinSeverity: nt.Severity, Heartbeat: time.Duration(nt.Heartbeat), On: map[state.Kind]bool{}}}
		on := nt.On
		if on == nil {
			for _, k := range DefaultOn {
				on = append(on, string(k))
			}
		}
		for _, k := range on {
			ch.Rule.On[state.Kind(k)] = true
		}
		switch nt.Type {
		case "telegram":
			ch.Notifier = &Telegram{Token: nt.BotToken, ChatID: nt.ChatID, HTTP: h}
			ch.Secrets = []string{nt.BotToken}
		case "discord":
			ch.Notifier = &Discord{URL: nt.Webhook, HTTP: h}
			ch.Secrets = []string{nt.Webhook, nt.Webhook[strings.LastIndexByte(nt.Webhook, '/')+1:]}
		case "webhook":
			ch.Notifier = &Webhook{URL: nt.URL, Secret: nt.Secret, HTTP: h}
			ch.Secrets = []string{nt.Secret, nt.URL}
		default:
			return nil, fmt.Errorf("unknown notifier type %q", nt.Type)
		}
		out = append(out, ch)
	}
	return out, nil
}

// KV persists per-channel delivery state; *state.Store implements it.
type KV interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
}

type Dispatcher struct {
	Channels []Channel
	KV       KV
	Logger   *slog.Logger
	Now      func() time.Time
	// Timeout bounds one channel's delivery, retries included.
	Timeout time.Duration
}

// maxPending caps undelivered changes kept per channel; beyond it the oldest
// are dropped so an unreachable channel can't grow the database forever.
const maxPending = 500

// Dispatch sends the diff to every channel concurrently; one failing channel
// never blocks the others. Changes a channel couldn't deliver are kept and
// sent with its next digest. It returns the failures, keyed by channel.
func (d *Dispatcher) Dispatch(ctx context.Context, diff *state.Diff) map[string]error {
	var (
		mu     sync.Mutex
		failed = map[string]error{}
		wg     sync.WaitGroup
	)
	for _, ch := range d.Channels {
		wg.Go(func() {
			if err := d.deliver(ctx, ch, diff); err != nil {
				err = redact(err, ch.Secrets)
				d.logger().Error("notification failed", "notifier", ch.Name, "error", err)
				mu.Lock()
				failed[ch.Name] = err
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return failed
}

func (d *Dispatcher) deliver(ctx context.Context, ch Channel, diff *state.Diff) error {
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(d.Timeout, 2*time.Minute))
	defer cancel()
	pendingKey, sentKey := "notify.pending."+ch.Name, "notify.last_sent."+ch.Name

	var pending []state.Change
	if v, ok, err := d.KV.Get(ctx, pendingKey); err != nil {
		return err
	} else if ok {
		if err := json.Unmarshal([]byte(v), &pending); err != nil {
			d.logger().Warn("dropping unreadable pending notifications", "notifier", ch.Name, "error", err)
		}
	}
	changes := merge(pending, ch.Rule.Filter(diff.Changes))

	msg := &Message{Event: EventDigest, RunID: diff.RunID, Started: diff.Started, Duration: diff.Duration,
		Targets: diff.Targets, Changes: changes, Open: diff.Open, Errors: len(diff.Errors), Notifier: ch.Name}
	if len(changes) == 0 {
		due, err := d.heartbeatDue(ctx, ch, sentKey)
		if err != nil || !due {
			return err
		}
		msg.Event = EventHeartbeat
	}

	if err := ch.Notifier.Send(ctx, msg); err != nil {
		if len(changes) > 0 {
			if len(changes) > maxPending {
				changes = changes[len(changes)-maxPending:]
			}
			data, _ := json.Marshal(changes)
			// A fresh context: the delivery's own may have run out.
			if serr := d.KV.Set(context.WithoutCancel(ctx), pendingKey, string(data)); serr != nil {
				err = errors.Join(err, serr)
			}
		}
		return err
	}
	if len(pending) > 0 {
		if err := d.KV.Delete(ctx, pendingKey); err != nil {
			return err
		}
	}
	return d.KV.Set(ctx, sentKey, d.now().UTC().Format(time.RFC3339))
}

func (d *Dispatcher) heartbeatDue(ctx context.Context, ch Channel, sentKey string) (bool, error) {
	if ch.Rule.Heartbeat <= 0 {
		return false, nil
	}
	v, ok, err := d.KV.Get(ctx, sentKey)
	switch {
	case err != nil:
		return false, err
	case !ok:
		return true, nil // never sent anything: confirm the setup works
	}
	last, err := time.Parse(time.RFC3339, v)
	return err != nil || d.now().Sub(last) >= ch.Rule.Heartbeat, nil
}

// merge adds this run's changes to undelivered ones. A finding's latest
// change wins, except that "persisting" doesn't hide an undelivered
// new/regressed.
func merge(pending, current []state.Change) []state.Change {
	if len(pending) == 0 {
		return current
	}
	index := make(map[string]int)
	out := slices.Clone(pending)
	for i, c := range out {
		index[c.Finding.Fingerprint()] = i
	}
	for _, c := range current {
		i, ok := index[c.Finding.Fingerprint()]
		switch {
		case !ok:
			index[c.Finding.Fingerprint()] = len(out)
			out = append(out, c)
		case c.Kind != state.Persisting || out[i].Kind == state.Persisting:
			out[i] = c
		}
	}
	slices.SortFunc(out, state.CompareChanges)
	return out
}

// Test sends a test message to each channel and returns the failures.
func Test(ctx context.Context, channels []Channel) map[string]error {
	failed := map[string]error{}
	for _, ch := range channels {
		if err := ch.Notifier.Send(ctx, &Message{Event: EventTest, Notifier: ch.Name, Started: time.Now()}); err != nil {
			failed[ch.Name] = redact(err, ch.Secrets)
		}
	}
	return failed
}

// redact replaces secrets in err's message. Error chains are flattened to
// text, since a wrapped error could still print the secret.
func redact(err error, secrets []string) error {
	msg := err.Error()
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return errors.New(msg)
}

func (d *Dispatcher) logger() *slog.Logger {
	if d.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Logger
}

func (d *Dispatcher) now() time.Time {
	if d.Now == nil {
		return time.Now()
	}
	return d.Now()
}
