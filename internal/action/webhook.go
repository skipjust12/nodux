package action

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skipjust12/nodux/internal/redact"
)

const (
	FormatJSON  = "json"
	FormatSlack = "slack"

	webhookAttempts  = 3
	webhookQueueSize = 100
)

type WebhookConfig struct {
	URL string
	// Format is "json" (the Record, as-is) or "slack" ({"text": ...},
	// also accepted by Mattermost, Rocket.Chat and Discord's /slack
	// endpoint).
	Format  string
	Headers map[string]string
	Timeout time.Duration
}

// WebhookAction POSTs alerts to an HTTP endpoint. In json format each
// alert is its own POST (the Record, as on the console); in slack
// format each notification is one message. Delivery happens on a
// background worker so a slow or dead endpoint never stalls the
// detection loops; Send only enqueues. Failed deliveries are retried on
// network errors, 5xx and 429, with backoff.
type WebhookAction struct {
	cfg     WebhookConfig
	client  *http.Client
	backoff time.Duration // first retry delay, doubles each attempt

	mu     sync.RWMutex // guards closed and the send on queue
	closed bool
	queue  chan Notification

	ctx    context.Context // cancelled if Close gives up draining
	cancel context.CancelFunc
	done   chan struct{}
}

func NewWebhook(cfg WebhookConfig) *WebhookAction {
	if cfg.Format == "" {
		cfg.Format = FormatJSON
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &WebhookAction{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.Timeout},
		backoff: time.Second,
		queue:   make(chan Notification, webhookQueueSize),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go w.worker()
	return w
}

func (w *WebhookAction) Name() string { return "webhook" }

func (w *WebhookAction) Send(_ context.Context, n Notification) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return errors.New("webhook action is closed")
	}
	select {
	case w.queue <- n:
		return nil
	default:
		return fmt.Errorf("webhook queue full (%d pending), dropping notification", webhookQueueSize)
	}
}

// Close stops accepting alerts and waits for queued ones to be
// delivered. If ctx expires first, in-flight deliveries are abandoned.
func (w *WebhookAction) Close(ctx context.Context) error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.mu.Unlock()

	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		w.cancel()
		<-w.done
		return fmt.Errorf("webhook: gave up delivering pending alerts: %w", ctx.Err())
	}
}

func (w *WebhookAction) worker() {
	defer close(w.done)
	for n := range w.queue {
		bodies, err := w.payloads(n)
		if err != nil {
			slog.Error("webhook payload", "error", err)
			continue
		}
		for _, body := range bodies {
			if err := w.deliver(body); err != nil {
				slog.Error("webhook delivery failed", "url", redact.URL(w.cfg.URL), "incident", n.IncidentID, "error", err)
			}
		}
	}
}

func (w *WebhookAction) deliver(body []byte) error {
	delay := w.backoff
	for attempt := 1; ; attempt++ {
		retry, err := w.post(body)
		if err == nil {
			return nil
		}
		if !retry || attempt == webhookAttempts {
			return fmt.Errorf("attempt %d/%d: %w", attempt, webhookAttempts, err)
		}
		select {
		case <-time.After(delay):
		case <-w.ctx.Done():
			return fmt.Errorf("attempt %d/%d: %w (shutting down)", attempt, webhookAttempts, err)
		}
		delay *= 2
	}
}

// post sends one request; retry says whether the failure is transient.
func (w *WebhookAction) post(body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(w.ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return false, redact.Err(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nodux")
	for k, v := range w.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		// The URL is often the credential (Slack, Discord): keep it out
		// of the error, which ends up in the logs.
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

// payloads is what to POST for a notification: one Slack message, or
// one JSON record per alert (or the digest record).
func (w *WebhookAction) payloads(n Notification) ([][]byte, error) {
	if w.cfg.Format == FormatSlack {
		b, err := json.Marshal(map[string]string{"text": slackNotification(n)})
		return [][]byte{b}, err
	}
	var out [][]byte
	if n.Digest != nil {
		b, err := json.Marshal(NewDigestRecord(n.Digest))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	for _, issue := range n.Alerts {
		b, err := json.Marshal(NewRecord(issue))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
