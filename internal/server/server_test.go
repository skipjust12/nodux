package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/engine"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/silence"
)

type fakeEngine struct {
	healthy  bool
	lastPoll time.Time
}

func (f *fakeEngine) Healthy() bool       { return f.healthy }
func (f *fakeEngine) LastPoll() time.Time { return f.lastPoll }
func (f *fakeEngine) Episodes() []engine.Episode {
	return []engine.Episode{
		{Detector: "crashloop", Severity: "critical", Container: "api", Message: "restarted 3 times", Since: time.Now().Add(-12 * time.Minute)},
		{Detector: "host_disk", Severity: "critical", Resource: "/", Message: "disk / at 95%", Since: time.Now().Add(-time.Hour), Silenced: true},
	}
}
func (f *fakeEngine) AlertCounts() map[engine.AlertKey]uint64 {
	return map[engine.AlertKey]uint64{{Detector: "crashloop", Severity: "critical", State: "firing"}: 4}
}

type fakeReceiver struct{}

func (fakeReceiver) Name() string { return `tele"gram` }
func (fakeReceiver) Stats() action.DeliveryStats {
	return action.DeliveryStats{Sent: 5, Failed: 1, Dropped: 2, Pending: 3}
}

type fakeLLM struct{}

func (fakeLLM) Budget() llm.Budget { return llm.Budget{MaxPerHour: 30, Remaining: 27, OK: 3} }

func source() *Source {
	return &Source{
		Engine:       &fakeEngine{healthy: true, lastPoll: time.Now()},
		Version:      "v1.2.3",
		Hostname:     "vps1",
		Started:      time.Unix(1700000000, 0),
		PollInterval: 15 * time.Second,
		Silences:     silence.New(),
		Receivers:    []Receiver{fakeReceiver{}},
		LLM:          fakeLLM{},
	}
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestMetrics(t *testing.T) {
	src := source()
	src.Silences.Add(silence.Matcher{Target: "api"}, time.Hour, "")
	code, body := get(t, Handler(src, false), "/metrics")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{
		`nodux_build_info{version="v1.2.3"} 1`,
		`nodux_start_time_seconds 1.7e+09`,
		`nodux_docker_up 1`,
		`nodux_healthy 1`,
		`nodux_active_episodes{detector="crashloop",severity="critical"} 1`,
		`nodux_silenced_episodes 1`,
		`nodux_alerts_total{detector="crashloop",severity="critical",state="firing",silenced="false"} 4`,
		`nodux_notifications_total{receiver="tele\"gram",result="failed"} 1`,
		`nodux_notification_queue_length{receiver="tele\"gram"} 3`,
		`nodux_silences 1`,
		`nodux_llm_budget_remaining 27`,
		`nodux_llm_requests_total{result="ok"} 3`,
		"# TYPE nodux_alerts_total counter",
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestHealthz(t *testing.T) {
	src := source()
	h := Handler(src, false)
	if code, body := get(t, h, "/healthz"); code != 200 || body != "ok\n" {
		t.Fatalf("healthy: %d %q", code, body)
	}
	src.Engine = &fakeEngine{healthy: true, lastPoll: time.Now().Add(-10 * time.Minute)}
	if code, body := get(t, h, "/healthz"); code != 503 || !strings.Contains(body, "no successful poll for 10m") {
		t.Fatalf("stalled: %d %q", code, body)
	}
	src.Engine = &fakeEngine{healthy: false}
	if code, body := get(t, h, "/healthz"); code != 503 || !strings.Contains(body, "docker daemon unreachable") {
		t.Fatalf("docker down: %d %q", code, body)
	}
	// The API isn't on the TCP handler.
	if code, _ := get(t, h, "/api/status"); code != 404 {
		t.Fatalf("/api/status on the metrics listener: %d", code)
	}
}

func TestControlSocketRoundTrip(t *testing.T) {
	dir, _ := os.MkdirTemp("", "nodux")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "run", "nodux.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	if _, err := ListenUnix(sock); err == nil {
		t.Fatal("second listener on a live socket should fail")
	}

	src := source()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Serve(ctx, ln, Handler(src, true)) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	c := NewClient(sock)
	s, err := c.AddSilence(ctx, SilenceRequest{Matcher: "api", Duration: "2d", Comment: "migration"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Matcher.Target != "api" || time.Until(s.Until) < 47*time.Hour {
		t.Fatalf("silence = %+v", s)
	}
	if _, err := c.AddSilence(ctx, SilenceRequest{Matcher: "color=red", Duration: "1h"}); err == nil || !strings.Contains(err.Error(), "bad matcher key") {
		t.Fatalf("bad matcher: %v", err)
	}
	if _, err := c.AddSilence(ctx, SilenceRequest{Matcher: "api", Duration: "soon"}); err == nil || !strings.Contains(err.Error(), "bad duration") {
		t.Fatalf("bad duration: %v", err)
	}

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Host != "vps1" || !st.DockerUp || len(st.Episodes) != 2 || len(st.Silences) != 1 || len(st.Receivers) != 1 ||
		st.Receivers[0].Sent != 5 || st.LLM == nil || st.LLM.Remaining != 27 {
		t.Fatalf("status = %+v", st)
	}

	if err := c.RemoveSilence(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveSilence(ctx, s.ID); err == nil || !strings.Contains(err.Error(), "no silence") {
		t.Fatalf("second remove: %v", err)
	}
	list, err := c.Silences(ctx)
	if err != nil || len(list) != 0 {
		t.Fatalf("list = %v, %v", list, err)
	}

	// Plain HTTP over the socket works too (curl --unix-socket).
	resp, err := c.http.Get("http://nodux/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "nodux_docker_up 1") {
		t.Errorf("metrics over the socket: %s", b)
	}
}

func TestClient_DaemonNotRunning(t *testing.T) {
	_, err := NewClient("/nonexistent/nodux.sock").Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is it running?") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"30m": 30 * time.Minute, "2h": 2 * time.Hour, "1d": 24 * time.Hour, "1h30m": 90 * time.Minute} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "-1h", "1x", "2dd"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q): expected an error", bad)
		}
	}
}
