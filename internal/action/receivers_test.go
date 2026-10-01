package action

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skipjust12/nodux/internal/detector"
)

type request struct {
	path   string
	header http.Header
	body   map[string]any
}

func capture(t *testing.T, status int) (*httptest.Server, chan request) {
	t.Helper()
	got := make(chan request, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		got <- request{r.URL.Path, r.Header, body}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestTelegram(t *testing.T) {
	srv, got := capture(t, 200)
	tg := NewTelegram(TelegramConfig{Name: "oncall", BotToken: "123:SECRET", ChatID: "-1001", ThreadID: 7, APIURL: srv.URL})
	tg.backoff = 0

	issue := testIssue()
	issue.Host = "vps1"
	issue.Container.Name = "api<1>"
	issue.Logs = []string{"a < b & c"}
	tg.Run(context.Background(), issue)
	resolved := issue
	resolved.Resolved = true
	tg.Run(context.Background(), resolved)
	closeAndWait(t, tg)

	r := <-got
	if r.path != "/bot123:SECRET/sendMessage" {
		t.Errorf("path = %q", r.path)
	}
	b := r.body
	if b["chat_id"] != "-1001" || b["parse_mode"] != "HTML" || b["message_thread_id"] != float64(7) || b["disable_notification"] != false {
		t.Errorf("body = %v", b)
	}
	text := b["text"].(string)
	if !strings.HasPrefix(text, "<b>[CRITICAL] oom</b> <code>api&lt;1&gt;</code> on vps1\ncontainer was killed") {
		t.Errorf("text = %q", text)
	}
	if !strings.HasSuffix(text, "<pre>a &lt; b &amp; c</pre>") {
		t.Errorf("logs not escaped/fenced: %q", text)
	}
	if r := <-got; r.body["disable_notification"] != true || !strings.HasPrefix(r.body["text"].(string), "<b>[RESOLVED] oom</b>") {
		t.Errorf("resolution: %v", r.body)
	}
	if s := tg.Stats(); s.Sent != 2 || s.Failed != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestTelegram_LongMessageFits(t *testing.T) {
	issue := testIssue()
	issue.Message = strings.Repeat("<", 3000)
	issue.Logs = []string{strings.Repeat("x", 300), strings.Repeat("y", 300)}
	text := telegramText(issue)
	if len(text) > telegramMaxMessage {
		t.Fatalf("%d bytes", len(text))
	}
	if strings.Count(text, "<pre>") != strings.Count(text, "</pre>") {
		t.Errorf("unbalanced tags: %q", text)
	}
}

func TestNtfy(t *testing.T) {
	srv, got := capture(t, 200)
	n, err := NewNtfy(NtfyConfig{URL: srv.URL + "/sub/alerts", Token: "tk"})
	if err != nil {
		t.Fatal(err)
	}
	issue := testIssue()
	issue.Analysis = "Heap grows."
	n.Run(context.Background(), issue)
	warn := issue
	warn.Severity = detector.SeverityWarning
	warn.Resolved = true
	n.Run(context.Background(), warn)
	closeAndWait(t, n)

	r := <-got
	if r.path != "/sub" || r.header.Get("Authorization") != "Bearer tk" {
		t.Errorf("path %q, auth %q", r.path, r.header.Get("Authorization"))
	}
	b := r.body
	if b["topic"] != "alerts" || b["title"] != "[CRITICAL] oom api" || b["priority"] != float64(5) {
		t.Errorf("body = %v", b)
	}
	if msg := b["message"].(string); !strings.HasPrefix(msg, "container was killed by the OOM killer\n\nHeap grows.\n\nl1\nl2") {
		t.Errorf("message = %q", msg)
	}
	if r := <-got; r.body["priority"] != float64(2) || r.body["title"] != "[RESOLVED] oom api" {
		t.Errorf("resolution: %v", r.body)
	}

	for _, bad := range []string{"https://ntfy.sh", "https://ntfy.sh/", "ntfy.sh/topic"} {
		if _, err := NewNtfy(NtfyConfig{URL: bad}); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if base, topic, _ := splitNtfyURL("https://u:p@ntfy.sh/alerts?x=1"); base != "https://u:p@ntfy.sh/" || topic != "alerts" {
		t.Errorf("split = %q %q", base, topic)
	}
}

type sink struct{ got []detector.Issue }

func (s *sink) Name() string { return "sink" }
func (s *sink) Run(_ context.Context, issue detector.Issue) error {
	s.got = append(s.got, issue)
	return nil
}

func TestRouted(t *testing.T) {
	crit := detector.Issue{Detector: "oom", Severity: detector.SeverityCritical}
	warn := detector.Issue{Detector: "memory", Severity: detector.SeverityWarning}
	resolved := warn
	resolved.Resolved = true
	silenced := crit
	silenced.Silenced = true
	host := detector.Issue{Detector: "host_disk", Severity: detector.SeverityCritical}

	for _, tt := range []struct {
		name  string
		route Route
		want  []string
	}{
		{"everything", Route{SendResolved: true}, []string{"oom", "memory", "memory", "host_disk"}},
		{"critical only", Route{Severities: []string{"critical"}, SendResolved: true}, []string{"oom", "host_disk"}},
		{"warnings, no resolutions", Route{Severities: []string{"warning"}}, []string{"memory"}},
		{"host detectors", Route{Detectors: []string{"host_*"}, SendResolved: true}, []string{"host_disk"}},
	} {
		s := &sink{}
		r := NewRouted(s, tt.route)
		for _, i := range []detector.Issue{crit, warn, resolved, silenced, host} {
			r.Run(context.Background(), i)
		}
		var names []string
		for _, i := range s.got {
			names = append(names, i.Detector)
		}
		if strings.Join(names, ",") != strings.Join(tt.want, ",") {
			t.Errorf("%s: got %v, want %v", tt.name, names, tt.want)
		}
	}
}

func TestRecord_Silenced(t *testing.T) {
	b, _ := json.Marshal(NewRecord(detector.Issue{Detector: "oom", Silenced: true}))
	if !strings.Contains(string(b), `"silenced":true`) {
		t.Errorf("record = %s", b)
	}
	b, _ = json.Marshal(NewRecord(detector.Issue{Detector: "oom"}))
	if strings.Contains(string(b), "silenced") {
		t.Errorf("record = %s", b)
	}
}

func TestHTTPAction_FailureAndDropCounts(t *testing.T) {
	srv, _ := capture(t, http.StatusBadRequest)
	w := newWebhook(t, WebhookConfig{URL: srv.URL})
	w.Run(context.Background(), testIssue())
	closeAndWait(t, w)
	if s := w.Stats(); s.Failed != 1 || s.Sent != 0 {
		t.Errorf("stats = %+v", s)
	}
}
