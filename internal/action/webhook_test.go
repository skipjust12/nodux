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

func one(issue detector.Issue) Notification {
	return Notification{Alerts: []detector.Issue{issue}}
}

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

func newWebhook(t *testing.T, cfg WebhookConfig) *HTTPAction {
	t.Helper()
	w := NewWebhook(cfg)
	w.backoff = time.Millisecond
	t.Cleanup(func() { w.Close(context.Background()) })
	return w
}

func closeAndWait(t *testing.T, w *HTTPAction) {
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
	if err := w.Send(context.Background(), one(testIssue())); err != nil {
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
	w.Send(context.Background(), one(testIssue()))
	closeAndWait(t, w)

	var msg map[string]string
	if err := json.Unmarshal(<-got, &msg); err != nil {
		t.Fatal(err)
	}
	text := msg["text"]
	if !strings.HasPrefix(text, "*[CRITICAL] oom* `api`: container was killed") {
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
	w.Send(context.Background(), one(testIssue()))
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
	w.Send(context.Background(), one(testIssue()))
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
	w.Send(context.Background(), one(testIssue()))
	closeAndWait(t, w)
	if n := calls.Load(); n != httpAttempts {
		t.Fatalf("calls = %d, want %d", n, httpAttempts)
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
	for i := 0; i < httpQueueSize+5; i++ {
		if err := w.Send(context.Background(), one(testIssue())); err != nil {
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
	if err := w.Send(context.Background(), one(testIssue())); err == nil {
		t.Fatal("Run after Close should fail")
	}
}

func TestWebhook_ErrorsDontLeakURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/services/T0/B0/SECRETTOKEN"
	srv.Close() // connection refused from here on

	w := newWebhook(t, WebhookConfig{URL: url})
	_, err := w.post([]byte("{}"))
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("error leaks the webhook URL: %v", err)
	}
}

func TestSlackText_ResolvedHostAndAnalysis(t *testing.T) {
	issue := testIssue()
	issue.Host = "vps1"
	issue.Analysis = "Heap grows without bound.\nCheck the cache size."
	text := slackText(issue, "")
	if !strings.HasPrefix(text, "*[CRITICAL] oom* `api` on vps1: ") {
		t.Errorf("text = %q", text)
	}
	if !strings.Contains(text, "\n> Heap grows without bound.\n> Check the cache size.") {
		t.Errorf("analysis not quoted: %q", text)
	}

	resolved := detector.Issue{Detector: "host_disk", Severity: detector.SeverityCritical, Resource: "/", Message: "resolved after 5m0s (was: disk / at 95%)", Resolved: true}
	if got := slackText(resolved, ""); got != "*[RESOLVED] host_disk* `/`: resolved after 5m0s (was: disk / at 95%)" {
		t.Errorf("resolved text = %q", got)
	}
}

func TestSlackText_FitsDiscordAndEscapesFences(t *testing.T) {
	issue := testIssue()
	issue.Message = strings.Repeat("m", 1100)
	issue.Logs = []string{
		strings.Repeat("a", 5000), strings.Repeat("b", 400), strings.Repeat("c", 400),
		"```rm -rf```", strings.Repeat("d", 400),
	}
	text := slackText(issue, "")
	if len(text) > slackMaxMessage {
		t.Fatalf("text is %d bytes, over %d", len(text), slackMaxMessage)
	}
	if strings.Contains(text, "aaaa") {
		t.Error("oldest lines should be dropped first")
	}
	if strings.Count(text, "```") != 2 {
		t.Errorf("a log line broke out of the code block: %q", text)
	}
}

func TestRecord_HostLevelOmitsContainerFields(t *testing.T) {
	b, _ := json.Marshal(NewRecord(detector.Issue{Detector: "host_disk", Severity: "critical", Message: "m", Resource: "/", Host: "vps1"}))
	s := string(b)
	for _, field := range []string{"container_id", "restart_count", "last_exit_code", "logs"} {
		if strings.Contains(s, field) {
			t.Errorf("host record has %s: %s", field, s)
		}
	}
	if !strings.Contains(s, `"state":"firing"`) || !strings.Contains(s, `"resource":"/"`) || !strings.Contains(s, `"host":"vps1"`) {
		t.Errorf("record = %s", s)
	}

	b, _ = json.Marshal(NewRecord(detector.Issue{Detector: "exit", Container: detector.ContainerSnapshot{ID: "c1"}, Resolved: true}))
	if s := string(b); !strings.Contains(s, `"restart_count":0`) || !strings.Contains(s, `"last_exit_code":0`) || !strings.Contains(s, `"state":"resolved"`) {
		t.Errorf("container record = %s", s)
	}
}
