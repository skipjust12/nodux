package action

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skipjust12/nodux/internal/redact"
)

const (
	httpAttempts  = 3
	httpQueueSize = 100
)

// HTTPAction delivers notifications as HTTP POSTs: a webhook, a
// Telegram bot, an ntfy topic. Delivery happens on a background worker
// so a slow or dead endpoint never stalls the detection loops; Send
// only enqueues. Failed deliveries are retried on network errors, 5xx
// and 429, with backoff, and drained on Close.
type HTTPAction struct {
	name    string
	url     string
	headers map[string]string
	// bodies renders a notification as the JSON bodies to POST: one
	// message, or one per alert (webhook in json format).
	bodies  func(n Notification) ([][]byte, error)
	client  *http.Client
	backoff time.Duration // first retry delay, doubles each attempt

	mu     sync.RWMutex // guards closed and the send on queue
	closed bool
	queue  chan Notification

	sent, failed, dropped atomic.Uint64

	ctx    context.Context // cancelled if Close gives up draining
	cancel context.CancelFunc
	done   chan struct{}
}

// DeliveryStats counts what happened to the messages an action was
// given.
type DeliveryStats struct {
	Sent    uint64 `json:"sent"`
	Failed  uint64 `json:"failed"`  // after retries
	Dropped uint64 `json:"dropped"` // queue full
	Pending int    `json:"pending"`
}

func newHTTPAction(name, url string, headers map[string]string, timeout time.Duration, bodies func(Notification) ([][]byte, error)) *HTTPAction {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &HTTPAction{
		name:    name,
		url:     url,
		headers: headers,
		bodies:  bodies,
		client:  &http.Client{Timeout: timeout},
		backoff: time.Second,
		queue:   make(chan Notification, httpQueueSize),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go a.worker()
	return a
}

func (a *HTTPAction) Name() string { return a.name }

func (a *HTTPAction) Send(_ context.Context, n Notification) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return fmt.Errorf("%s is closed", a.name)
	}
	select {
	case a.queue <- n:
		return nil
	default:
		a.dropped.Add(1)
		return fmt.Errorf("%s queue full (%d pending), dropping notification", a.name, httpQueueSize)
	}
}

func (a *HTTPAction) Stats() DeliveryStats {
	return DeliveryStats{
		Sent:    a.sent.Load(),
		Failed:  a.failed.Load(),
		Dropped: a.dropped.Load(),
		Pending: len(a.queue),
	}
}

// Close stops accepting notifications and waits for queued ones to be
// delivered. If ctx expires first, in-flight deliveries are abandoned.
func (a *HTTPAction) Close(ctx context.Context) error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.queue)
	}
	a.mu.Unlock()

	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		a.cancel()
		<-a.done
		return fmt.Errorf("%s: gave up delivering pending alerts: %w", a.name, ctx.Err())
	}
}

func (a *HTTPAction) worker() {
	defer close(a.done)
	for n := range a.queue {
		bodies, err := a.bodies(n)
		if err != nil {
			a.failed.Add(1)
			slog.Error("rendering notification failed", "action", a.name, "incident", n.IncidentID, "error", err)
			continue
		}
		for _, body := range bodies {
			if err := a.deliver(body); err != nil {
				a.failed.Add(1)
				slog.Error("alert delivery failed", "action", a.name, "url", redact.URL(a.url), "incident", n.IncidentID, "error", err)
				continue
			}
			a.sent.Add(1)
		}
	}
}

func (a *HTTPAction) deliver(body []byte) error {
	delay := a.backoff
	for attempt := 1; ; attempt++ {
		retry, err := a.post(body)
		if err == nil {
			return nil
		}
		if !retry || attempt == httpAttempts {
			return fmt.Errorf("attempt %d/%d: %w", attempt, httpAttempts, err)
		}
		select {
		case <-time.After(delay):
		case <-a.ctx.Done():
			return fmt.Errorf("attempt %d/%d: %w (shutting down)", attempt, httpAttempts, err)
		}
		delay *= 2
	}
}

// post sends one request; retry says whether the failure is transient.
func (a *HTTPAction) post(body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(a.ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return false, redact.Err(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nodux")
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		// The URL is often the credential (Slack, Discord, a Telegram
		// bot token): keep it out of the error, which ends up in the logs.
		return true, redact.Err(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		io.Copy(io.Discard, resp.Body)
		return false, nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	err = fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests, err
}
