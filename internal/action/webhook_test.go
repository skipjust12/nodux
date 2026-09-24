package action

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

func testIssue() detector.Issue {
	return detector.Issue{
		Detector: "oom",
		Severity: detector.SeverityCritical,
		Message:  "container was killed by the OOM killer",
		Container: detector.ContainerSnapshot{
			ID: "abc", Name: "api", OOMKilled: true, MemoryUsed: 60, MemoryLimit: 64,
		},
		DetectedAt: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
		Logs:       []string{"l1", "l2", "l3", "l4", "l5", "l6", "l7"},
	}
}

type captured struct {
	header http.Header
	body   []byte
}

func newWebhook(t *testing.T, cfg WebhookConfig) *WebhookAction {
	t.Helper()
	w := NewWebhook(cfg)
	w.backoff = time.Millisecond
	t.Cleanup(func() { w.Close(context.Background()) })
	return w
}

func closeAndWait(t *testing.T, w *WebhookAction) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestWebhook_JSONPayloadAndHeaders(t *testing.T) {
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{r.Header, body}
	}))
	defer srv.Close()

	w := newWebhook(t, WebhookConfig{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer s3cret"}})
	if err := w.Run(context.Background(), testIssue()); err != nil {
		t.Fatal(err)
	}
	closeAndWait(t, w)

	c := <-got
	if c.header.Get("Authorization") != "Bearer s3cret" || c.header.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", c.header)
	}
	var rec Record
	if err := json.Unmarshal(c.body, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Detector != "oom" || rec.ContainerName != "api" || !rec.OOMKilled || rec.MemoryLimit != 64 || len(rec.Logs) != 7 {
		t.Errorf("record = %+v", rec)
	}
	if rec.Timestamp != "2026-09-24T12:00:00Z" {
		t.Errorf("timestamp = %q", rec.Timestamp)
	}
}

func TestWebhook_SlackFormat(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
	}))
	defer srv.Close()

	w := newWebhook(t, WebhookConfig{URL: srv.URL, Format: FormatSlack})
	w.Run(context.Background(), testIssue())
	closeAndWait(t, w)

	var msg map[string]string
	if err := json.Unmarshal(<-got, &msg); err != nil {
		t.Fatal(err)
	}
	text := msg["text"]
	if !strings.HasPrefix(text, "*[CRITICAL] oom* on `api`: container was killed") {
		t.Errorf("text = %q", text)
	}
	if !strings.Contains(text, "l3\nl4\nl5\nl6\nl7") || strings.Contains(text, "l2") {
		t.Errorf("expected only the last %d log lines: %q", slackLogLines, text)
	}
}

func TestWebhook_RetriesTransientFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(rw, "upstream hiccup", http.StatusBadGateway)
		}
	}))
	defer srv.Close()

	w := newWebhook(t, WebhookConfig{URL: srv.URL})
	w.Run(context.Background(), testIssue())
	closeAndWait(t, w)
	if n := calls.Load(); n != 3 {
		t.Fatalf("calls = %d, want 3 (two 502s, then success)", n)
	}
}

func TestWebhook_DoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(rw, "bad token", http.StatusUnauthorized)
	}))
	defer srv.Close()

	w := newWebhook(t, WebhookConfig{URL: srv.URL})
	w.Run(context.Background(), testIssue())
	closeAndWait(t, w)
	if n := calls.Load(); n != 1 {
		t.Fatalf("calls = %d, want 1", n)
	}
}

func TestWebhook_GivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		rw.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	w := newWebhook(t, WebhookConfig{URL: srv.URL})
	w.Run(context.Background(), testIssue())
	closeAndWait(t, w)
	if n := calls.Load(); n != webhookAttempts {
		t.Fatalf("calls = %d, want %d", n, webhookAttempts)
	}
}

func TestWebhook_RunNeverBlocksAndCloseAbandonsHungEndpoint(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	w := newWebhook(t, WebhookConfig{URL: srv.URL, Timeout: time.Minute})

	// One in flight, the queue full, the next one dropped: Run must
	// never block the detection loops.
	start := time.Now()
	var dropped int
	for i := 0; i < webhookQueueSize+5; i++ {
		if err := w.Run(context.Background(), testIssue()); err != nil {
			dropped++
		}
	}
	if time.Since(start) > time.Second {
		t.Fatal("Run blocked")
	}
	if dropped == 0 {
		t.Fatal("expected alerts to be dropped once the queue is full")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := w.Close(ctx); err == nil {
		t.Fatal("expected Close to report abandoned alerts")
	}
	if err := w.Run(context.Background(), testIssue()); err == nil {
		t.Fatal("Run after Close should fail")
	}
}
