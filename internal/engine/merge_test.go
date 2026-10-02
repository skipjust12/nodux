package engine

import (
	"context"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/dockertest"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/incident"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/silence"
)

// A silenced alert goes straight to the local log: it doesn't join, hold
// up or get analyzed with an incident, and isn't written to the history.
func TestEngine_SilencedAlertsSkipIncidents(t *testing.T) {
	srv := dockertest.New(t)
	srv.AddContainer(container("c1", "api", "exited"), "boom")
	srv.AddContainer(container("c2", "worker", "exited"), "boom")
	stream := srv.NewStream()

	store := silence.New()
	store.Add(silence.Matcher{Target: "worker"}, time.Hour, "")
	hist, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer hist.Close()

	notes := &noteRecorder{notes: make(chan action.Notification, 8)}
	analyzer := &fakeAnalyzer{seen: make(chan llm.Incident, 4)}
	_, eng, _ := runUntilStopped(t, srv, Options{
		EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)},
		Actions:        []action.Action{notes},
		Grouping:       incident.Config{Enabled: true, GroupWait: 300 * time.Millisecond, Window: time.Minute},
		Analyzer:       analyzer,
		History:        hist,
		Silences:       store,
	})

	now := time.Now()
	stream <- event("c2", "worker", "die", map[string]string{"exitCode": "1"}, now)
	stream <- event("c1", "api", "die", map[string]string{"exitCode": "1"}, now.Add(time.Millisecond))

	// The silenced one arrives right away, on its own and without logs.
	n := notes.next(t)
	if len(n.Alerts) != 1 || n.IncidentID != 0 || !n.Alerts[0].Silenced || n.Alerts[0].Container.Name != "worker" || n.Alerts[0].Logs != nil {
		t.Fatalf("silenced notification: %+v", n)
	}
	// The other one waits for its incident, alone.
	n = notes.next(t)
	if len(n.Alerts) != 1 || n.IncidentID == 0 || n.Alerts[0].Container.Name != "api" || n.Alerts[0].Silenced {
		t.Fatalf("incident: %+v", n)
	}
	inc := <-analyzer.seen
	if len(inc.Alerts) != 1 || inc.Alerts[0].Container.Name != "api" {
		t.Errorf("analyzed: %+v", inc.Alerts)
	}
	select {
	case inc := <-analyzer.seen:
		t.Errorf("silenced alert analyzed: %+v", inc.Alerts)
	case <-time.After(100 * time.Millisecond):
	}

	rows, err := hist.Alerts(context.Background(), history.Query{Since: now.Add(-time.Minute)})
	if err != nil || len(rows) != 1 || rows[0].Subject != "api" {
		t.Errorf("history = %+v, %v", rows, err)
	}
	counts := eng.AlertCounts()
	if counts[AlertKey{Detector: "exit", Severity: "warning", State: "firing", Silenced: true}] != 1 ||
		counts[AlertKey{Detector: "exit", Severity: "warning", State: "firing"}] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

// Silences, and alerts they hold back, survive a restart: the held
// alert isn't lost, and isn't sent while the silence lasts.
func TestEngine_RestartKeepsSilencesAndHeldAlerts(t *testing.T) {
	srv := dockertest.New(t)
	sick := container("c1", "web", "running")
	sick.State.Health = &dockerclient.Health{Status: "unhealthy", FailingStreak: 2}
	srv.AddContainer(sick)
	dir := t.TempDir()
	opts := func(store *silence.Store) Options {
		return Options{Detectors: []detector.Detector{detector.NewUnhealthyDetector()}, State: openState(t, dir), Silences: store}
	}

	first := silence.New()
	sil, _ := first.Add(silence.Matcher{Target: "web"}, time.Hour, "maintenance")
	rec, _, stop := runUntilStopped(t, srv, opts(first))
	if issue := rec.next(t); !issue.Silenced {
		t.Fatalf("expected a silenced alert: %+v", issue)
	}
	stop()

	second := silence.New()
	rec, eng, _ := runUntilStopped(t, srv, opts(second))
	waitFor(t, func() bool { return !eng.LastPoll().IsZero() })
	if list := second.List(); len(list) != 1 || list[0].ID != sil.ID || list[0].Comment != "maintenance" {
		t.Fatalf("silences after restart: %+v", list)
	}
	if eps := eng.Episodes(); len(eps) != 1 || !eps[0].Silenced {
		t.Fatalf("episodes after restart: %+v", eps)
	}
	rec.none(t, 100*time.Millisecond)

	second.Remove(sil.ID)
	if issue := rec.next(t); issue.Silenced || issue.Resolved || issue.Container.Name != "web" {
		t.Fatalf("held alert after the silence: %+v", issue)
	}
}
