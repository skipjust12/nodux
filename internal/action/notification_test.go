package action

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

func batch() Notification {
	oom := testIssue()
	oom.Host = "vps1"
	oom.IncidentID = 4
	oom.Analysis = "api leaks memory"
	host := detector.Issue{Detector: "host_memory", Severity: "warning", Resource: "memory", Message: "host memory at 95%", Host: "vps1", IncidentID: 4, Analysis: "api leaks memory"}
	old := detector.Issue{Detector: "unhealthy", Severity: "warning", Container: detector.ContainerSnapshot{ID: "w1", Name: "worker"}, Message: "resolved after 3m", Resolved: true, IncidentID: 4}
	return Notification{IncidentID: 4, Update: true, Alerts: []detector.Issue{oom, host, old}, Summary: "api leaks memory"}
}

func TestSlackNotification_Batch(t *testing.T) {
	text := slackNotification(batch())
	for _, want := range []string{
		"*[CRITICAL] incident #4* (update) on vps1: 2 new, 1 resolved",
		"\n> api leaks memory",
		"\n• *oom* `api`: container was killed",
		"\n• *host_memory* `memory`: host memory at 95%",
		"\n• resolved *unhealthy* `worker`: resolved after 3m",
		"l7\n```",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if len(text) > slackMaxMessage {
		t.Errorf("text is %d bytes", len(text))
	}
}

func TestSlackNotification_SingleAlertKeepsFormat(t *testing.T) {
	n := one(testIssue())
	if got, want := slackNotification(n), slackText(testIssue(), ""); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	n.IncidentID, n.Update = 9, true
	if got := slackNotification(n); !strings.HasPrefix(got, "*[CRITICAL] oom* `api` (incident #9): ") {
		t.Errorf("update of a single alert: %q", got)
	}
}

func TestSlackNotification_HugeBatchFits(t *testing.T) {
	var alerts []detector.Issue
	for i := 0; i < 50; i++ {
		a := testIssue()
		a.Message = strings.Repeat("m", 400)
		alerts = append(alerts, a)
	}
	if text := slackNotification(Notification{IncidentID: 1, Alerts: alerts}); len(text) > slackMaxMessage {
		t.Fatalf("text is %d bytes", len(text))
	}
}

func digest() *Digest {
	return &Digest{
		Host: "vps1", Title: "Daily digest",
		From: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
		Text: "*Daily digest*: quiet day", Data: map[string]int{"alerts": 0},
	}
}

func TestConsole_AlertsAndDigest(t *testing.T) {
	var buf bytes.Buffer
	c := &ConsoleAction{out: &buf}
	b := batch()
	b.Digest = nil
	if err := c.Send(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), Notification{Digest: digest()}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %q", lines)
	}
	var rec Record
	json.Unmarshal([]byte(lines[0]), &rec)
	if rec.Kind != "alert" || rec.IncidentID != 4 || rec.Analysis != "api leaks memory" {
		t.Errorf("record = %+v", rec)
	}
	var d DigestRecord
	json.Unmarshal([]byte(lines[3]), &d)
	if d.Kind != "digest" || d.From != "2026-09-30T09:00:00Z" || d.Text == "" || d.Data == nil {
		t.Errorf("digest = %+v", d)
	}
}

func TestWebhook_JSONPostsEachAlertAndDigest(t *testing.T) {
	got := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
	}))
	defer srv.Close()

	w := newWebhook(t, WebhookConfig{URL: srv.URL})
	w.Send(context.Background(), batch())
	w.Send(context.Background(), Notification{Digest: digest()})
	closeAndWait(t, w)
	close(got)

	var kinds []string
	for body := range got {
		var m map[string]any
		json.Unmarshal(body, &m)
		kinds = append(kinds, m["kind"].(string))
	}
	if strings.Join(kinds, ",") != "alert,alert,alert,digest" {
		t.Errorf("posted %v", kinds)
	}
}

func TestWebhook_SlackDigest(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
	}))
	defer srv.Close()
	w := newWebhook(t, WebhookConfig{URL: srv.URL, Format: FormatSlack})
	w.Send(context.Background(), Notification{Digest: digest()})
	closeAndWait(t, w)
	var msg map[string]string
	json.Unmarshal(<-got, &msg)
	if msg["text"] != "*Daily digest*: quiet day" {
		t.Errorf("text = %q", msg["text"])
	}
}
