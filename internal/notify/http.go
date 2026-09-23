package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// HTTP posts to notification endpoints, retrying on rate limits (honoring
// the server's retry-after), server errors and network errors.
type HTTP struct {
	Client    *http.Client
	UserAgent string
	// MaxAttempts defaults to 5.
	MaxAttempts int
	// Sleep waits between attempts; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

const (
	backoffBase = time.Second
	backoffCap  = 30 * time.Second
	// maxRetryAfter: a longer rate limit fails the delivery, which is then
	// retried with the next run.
	maxRetryAfter = 5 * time.Minute
)

func NewHTTP(userAgent string, blockPrivate bool) *HTTP {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
	}
	if blockPrivate {
		// Checked at connect time, after DNS, so rebinding can't sneak an
		// internal address past it. A proxy would bypass the check.
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, _ := net.SplitHostPort(address)
			if a, err := netip.ParseAddr(host); err != nil || !publicAddr(a) {
				return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
			}
			return nil
		}
		transport.Proxy = nil
	}
	return &HTTP{
		Client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			// Redirects would dodge the address check and resend payloads.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		UserAgent: userAgent,
	}
}

var ErrPrivateAddress = errors.New("refusing to connect to a non-public address")

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// StatusError is a response the server rejected.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

// Post sends body as JSON and returns the response body of a 2xx reply.
func (h *HTTP) Post(ctx context.Context, rawURL string, body []byte, header http.Header) ([]byte, error) {
	attempts := cmpOrInt(h.MaxAttempts, 5)
	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			wait := backoff(attempt)
			var se *StatusError
			if errors.As(lastErr, &se) && se.Status == http.StatusTooManyRequests {
				wait = retryAfter(lastErr)
				if wait > maxRetryAfter {
					return nil, fmt.Errorf("rate limited for %s: %w", wait, lastErr)
				}
			}
			if err := h.sleep(ctx, wait); err != nil {
				return nil, errors.Join(lastErr, err)
			}
		}
		resp, err := h.once(ctx, rawURL, body, header)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var se *StatusError
		if errors.As(err, &se) && se.Status != http.StatusTooManyRequests && se.Status < 500 {
			return nil, err // the request itself is wrong; retrying won't help
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
}

// retryAfterError carries the server's requested delay.
type retryAfterError struct {
	*StatusError
	after time.Duration
}

func (e *retryAfterError) Unwrap() error { return e.StatusError }

func retryAfter(err error) time.Duration {
	var ra *retryAfterError
	if errors.As(err, &ra) && ra.after > 0 {
		return ra.after
	}
	return backoffCap
}

func (h *HTTP) once(ctx context.Context, rawURL string, body []byte, header http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", h.UserAgent)
	resp, err := h.Client.Do(req)
	if err != nil {
		// url.Error repeats the URL, which holds tokens for Telegram and Discord.
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, ue.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 == 2 {
		return data, nil
	}
	se := &StatusError{Status: resp.StatusCode, Body: snippet(data)}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &retryAfterError{se, parseRetryAfter(resp.Header.Get("Retry-After"), data)}
	}
	return nil, se
}

// parseRetryAfter reads the Retry-After header or the JSON retry_after field
// that Discord (seconds, fractional) and Telegram (parameters.retry_after)
// send.
func parseRetryAfter(header string, body []byte) time.Duration {
	if secs, err := strconv.ParseFloat(header, 64); err == nil && secs >= 0 {
		return time.Duration(secs * float64(time.Second))
	}
	var v struct {
		RetryAfter float64 `json:"retry_after"`
		Parameters struct {
			RetryAfter float64 `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(body, &v) == nil {
		if secs := max(v.RetryAfter, v.Parameters.RetryAfter); secs > 0 {
			return time.Duration(secs * float64(time.Second))
		}
	}
	return 0
}

func snippet(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// backoff is exponential with full jitter.
func backoff(attempt int) time.Duration {
	ceiling := min(backoffCap, backoffBase<<(attempt-1))
	return time.Duration(rand.Int64N(int64(ceiling)) + 1)
}

func (h *HTTP) sleep(ctx context.Context, d time.Duration) error {
	if h.Sleep != nil {
		return h.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cmpOrInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
