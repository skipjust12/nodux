package engine

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/dockertest"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/incident"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/state"
)

// noteRecorder keeps whole notifications, for grouping tests.
type noteRecorder struct {
	notes chan action.Notification
}

func (r *noteRecorder) Name() string { return "notes" }

func (r *noteRecorder) Send(_ context.Context, n action.Notification) error {
	r.notes <- n
	return nil
}

func (r *noteRecorder) next(t *testing.T) action.Notification {
	t.Helper()
	select {
	case n := <-r.notes:
		return n
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a notification")
		return action.Notification{}
	}
}

// runUntilStopped starts an engine; stop shuts it down and waits for it,
// final state save included.
func runUntilStopped(t *testing.T, srv *dockertest.Server, opts Options) (rec *recorder, eng *Engine, stop func()) {
	t.Helper()
	rec = &recorder{issues: make(chan detector.Issue, 32)}
	opts.Actions = append(opts.Actions, rec)
	if opts.PollInterval == 0 {
		opts.PollInterval = 20 * time.Millisecond
	}
	eng = New(dockerclient.New(srv.SocketPath), opts)
	eng.minBackoff = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		eng.Run(ctx)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}
	t.Cleanup(stop)
	return rec, eng, stop
}

func openState(t *testing.T, dir string) *state.File {
	t.Helper()
	f, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestEngine_RestartKeepsEpisodes(t *testing.T) {
	srv := dockertest.New(t)
	sick := func(id, name string) *dockerclient.ContainerInspect {
		c := container(id, name, "running")
		c.State.Health = &dockerclient.Health{Status: "unhealthy", FailingStreak: 3}
		return c
	}
	srv.AddContainer(sick("c1", "web"))
	srv.AddContainer(sick("c2", "db"))
	srv.AddContainer(sick("c3", "cache"))
	dir := t.TempDir()
	opts := func() Options {
		return Options{Detectors: []detector.Detector{detector.NewUnhealthyDetector()}, State: openState(t, dir)}
	}

	rec, _, stop := runUntilStopped(t, srv, opts())
	for i := 0; i < 3; i++ {
		rec.next(t)
	}
	stop()

	// While nodux is down: web stays broken, db gets fixed, cache is removed.
	healthy := container("c2", "db", "running")
	healthy.State.Health = &dockerclient.Health{Status: "healthy"}
	srv.AddContainer(healthy)
	srv.RemoveContainer("c3")

	rec, eng, _ := runUntilStopped(t, srv, opts())
	got := map[string]detector.Issue{}
	for i := 0; i < 2; i++ {
		issue := rec.next(t)
		got[issue.Container.Name] = issue
	}
	if db := got["db"]; !db.Resolved || !strings.HasPrefix(db.Message, "resolved after") || db.Key != "unhealthy/c2" {
		t.Errorf("db: %+v", db)
	}
	if cache := got["cache"]; !cache.Resolved || !strings.HasPrefix(cache.Message, "container removed after") {
		t.Errorf("cache: %+v", cache)
	}
	rec.none(t, 150*time.Millisecond) // web: still broken, already reported

	open := eng.ActiveAlerts()
	if len(open) != 1 || open[0].Container.Name != "web" || open[0].DetectedAt.IsZero() {
		t.Fatalf("active = %+v", open)
	}
}

func TestEngine_RestartResumesEventStream(t *testing.T) {
	srv := dockertest.New(t)
	stream := srv.NewStream()
	dir := t.TempDir()
	opts := func() Options {
		return Options{
			EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)},
			State:          openState(t, dir),
		}
	}

	rec, _, stop := runUntilStopped(t, srv, opts())
	t0 := time.Now().Add(-time.Minute)
	crash := event("a", "api", "die", map[string]string{"exitCode": "1"}, t0)
	stream <- crash
	rec.next(t)
	<-srv.EventQueries
	// A stop requested just before nodux goes down...
	stream <- event("b", "db", "kill", map[string]string{"signal": "15"}, t0.Add(time.Second))
	time.Sleep(50 * time.Millisecond)
	stop()

	second := srv.NewStream()
	rec, _, _ = runUntilStopped(t, srv, opts())
	q, _ := url.ParseQuery(<-srv.EventQueries)
	if want := formatSince(t0.Add(time.Second)); q.Get("since") != want {
		t.Fatalf("resumed since = %q, want %q", q.Get("since"), want)
	}
	// ...and the replay includes what was already handled.
	second <- crash
	second <- event("b", "db", "die", map[string]string{"exitCode": "143"}, t0.Add(2*time.Second))
	second <- event("c", "worker", "die", map[string]string{"exitCode": "2"}, t0.Add(3*time.Second))
	if issue := rec.next(t); issue.Container.Name != "worker" {
		t.Fatalf("expected only the worker crash, got %+v", issue)
	}
	rec.none(t, 100*time.Millisecond)
}

func TestEngine_RestartResolvesDockerOutage(t *testing.T) {
	srv := dockertest.New(t)
	srv.SetDown(true)
	dir := t.TempDir()
	rec, _, stop := runUntilStopped(t, srv, Options{DockerDownAfter: 20 * time.Millisecond, State: openState(t, dir)})
	if issue := rec.next(t); issue.Detector != "docker" || issue.Resolved {
		t.Fatalf("unexpected: %+v", issue)
	}
	stop()

	srv.SetDown(false)
	rec, _, _ = runUntilStopped(t, srv, Options{DockerDownAfter: 20 * time.Millisecond, State: openState(t, dir)})
	if issue := rec.next(t); issue.Detector != "docker" || !issue.Resolved {
		t.Fatalf("outage that ended while nodux was down not resolved: %+v", issue)
	}
}

func TestEngine_RestartDropsEpisodesOfDisabledDetectors(t *testing.T) {
	srv := dockertest.New(t)
	sick := container("c1", "web", "running")
	sick.State.Health = &dockerclient.Health{Status: "unhealthy"}
	srv.AddContainer(sick)
	dir := t.TempDir()
	rec, _, stop := runUntilStopped(t, srv, Options{Detectors: []detector.Detector{detector.NewUnhealthyDetector()}, State: openState(t, dir)})
	rec.next(t)
	stop()

	_, eng, _ := runUntilStopped(t, srv, Options{State: openState(t, dir)})
	time.Sleep(50 * time.Millisecond)
	if open := eng.ActiveAlerts(); len(open) != 0 {
		t.Fatalf("episode of a disabled detector restored: %+v", open)
	}
}

func TestEngine_RestartDropsEpisodesOfExcludedContainers(t *testing.T) {
	srv := dockertest.New(t)
	sick := container("c1", "web", "running")
	sick.State.Health = &dockerclient.Health{Status: "unhealthy"}
	srv.AddContainer(sick)
	dir := t.TempDir()
	opts := Options{Detectors: []detector.Detector{detector.NewUnhealthyDetector()}, State: openState(t, dir)}
	rec, _, stop := runUntilStopped(t, srv, opts)
	rec.next(t)
	stop()

	opts.State, opts.ExcludeContainers = openState(t, dir), []string{"web"}
	_, eng, _ := runUntilStopped(t, srv, opts)
	time.Sleep(50 * time.Millisecond)
	if open := eng.ActiveAlerts(); len(open) != 0 {
		t.Fatalf("episode of a now-excluded container restored: %+v", open)
	}
}

func TestEngine_Labels(t *testing.T) {
	srv := dockertest.New(t)
	optOut := container("c1", "vault", "running")
	optOut.Config.Labels = map[string]string{"nodux.enable": "false"}
	optOut.State.Health = &dockerclient.Health{Status: "unhealthy"}
	srv.AddContainer(optOut)
	noHealth := container("c2", "flaky", "running")
	noHealth.Config.Labels = map[string]string{"nodux.unhealthy.enable": "false"}
	noHealth.State.Health = &dockerclient.Health{Status: "unhealthy"}
	srv.AddContainer(noHealth)
	expected := container("c3", "api", "exited")
	expected.Config.Labels = map[string]string{"nodux.expected": "true"}
	srv.AddContainer(expected)
	stream := srv.NewStream()

	rec := start(t, srv, Options{
		Detectors:      []detector.Detector{detector.NewUnhealthyDetector()},
		EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)},
		Expected:       detector.NewExpectedDetector(nil, 0),
	})
	issue := rec.next(t)
	if issue.Detector != "expected" || issue.Container.Name != "api" {
		t.Fatalf("unexpected: %+v", issue)
	}

	// Events carry labels as attributes; when they don't (Podman), the
	// labels seen by the last poll apply.
	now := time.Now()
	stream <- event("c1", "vault", "die", map[string]string{"exitCode": "1", "nodux.enable": "false"}, now)
	stream <- event("c1", "vault", "die", map[string]string{"exitCode": "1"}, now.Add(time.Millisecond))
	stream <- event("c2", "flaky", "die", map[string]string{"exitCode": "1", "nodux.exit.enable": "false"}, now.Add(2*time.Millisecond))
	rec.none(t, 150*time.Millisecond)
}

func TestEngine_GroupsIncidentsAndRecordsHistory(t *testing.T) {
	srv := dockertest.New(t)
	api := container("c1", "api", "running")
	api.Config.Image = "api:latest"
	api.Image = "sha256:2222222222222222"
	api.Config.Labels = map[string]string{"com.docker.compose.project": "shop"}
	srv.AddContainer(api, "panic: out of memory")
	db := container("c2", "db", "running")
	db.Config.Labels = map[string]string{"com.docker.compose.project": "shop"}
	srv.AddContainer(db)
	srv.AddContainer(container("c3", "blog", "running"))
	stream := srv.NewStream()

	store, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.AddAlerts(context.Background(), []history.Alert{{Time: time.Now().Add(-24 * time.Hour), State: "firing", Detector: "oom", Severity: "critical", Subject: "api", Container: true, Message: "killed yesterday"}})

	notes := &noteRecorder{notes: make(chan action.Notification, 8)}
	analyzer := &fakeAnalyzer{seen: make(chan llm.Incident, 4)}
	_, eng, _ := runUntilStopped(t, srv, Options{
		EventDetectors: []detector.EventDetector{detector.NewOOMDetector(), detector.NewExitDetector([]int{0}, true)},
		Actions:        []action.Action{notes},
		Grouping:       incident.Config{Enabled: true, GroupWait: 200 * time.Millisecond, Window: time.Minute},
		Analyzer:       analyzer,
		History:        store,
	})
	// The image changed since nodux last saw the container.
	eng.mu.Lock()
	eng.images["api"] = &imageInfo{Image: "api:latest", ImageID: "sha256:1111111111111111", Since: time.Now().Add(-time.Hour)}
	eng.mu.Unlock()

	now := time.Now()
	stream <- event("c1", "api", "start", nil, now)
	stream <- event("c1", "api", "oom", nil, now.Add(2*time.Second))
	stream <- event("c2", "db", "die", map[string]string{"exitCode": "1", "com.docker.compose.project": "shop"}, now.Add(2*time.Second+time.Millisecond))
	stream <- event("c3", "blog", "die", map[string]string{"exitCode": "1"}, now.Add(2*time.Second+2*time.Millisecond))

	byID := map[int64]action.Notification{}
	for i := 0; i < 2; i++ {
		n := notes.next(t)
		byID[n.IncidentID] = n
	}
	shop, blog := byID[1], byID[2]
	if len(shop.Alerts) != 2 || len(blog.Alerts) != 1 {
		t.Fatalf("grouping: %+v", byID)
	}
	if shop.Summary != "the database is down" || shop.Alerts[0].Analysis != shop.Summary || shop.Alerts[0].IncidentID != 1 {
		t.Errorf("summary not attached: %+v", shop)
	}

	var inc llm.Incident
	for i := 0; i < 2; i++ {
		if got := <-analyzer.seen; got.ID == 1 {
			inc = got
		}
	}
	f := inc.Containers["api"]
	if f.PrevImage != "api:latest (111111111111)" || f.ImageChangedAt.IsZero() {
		t.Errorf("image change not passed on: %+v", f)
	}
	if len(f.History) != 1 || f.History[0].Message != "killed yesterday" {
		t.Errorf("history not passed on: %+v", f.History)
	}
	for _, a := range inc.Alerts {
		if a.Detector == "oom" && a.Container.LastRun != 2*time.Second {
			t.Errorf("last run = %v", a.Container.LastRun)
		}
	}

	time.Sleep(50 * time.Millisecond)
	rows, _ := store.Alerts(context.Background(), history.Query{Since: now.Add(-time.Minute)})
	if len(rows) != 3 {
		t.Fatalf("history rows = %+v", rows)
	}
	for _, r := range rows {
		if r.IncidentID == 0 || (r.Subject == "api" && r.Analysis != "the database is down") {
			t.Errorf("row = %+v", r)
		}
	}
}

func TestEngine_RecordsMemorySamples(t *testing.T) {
	srv := dockertest.New(t)
	srv.AddContainer(container("c1", "api", "running"))
	srv.AddContainer(container("c2", "old", "exited"))
	st := &dockerclient.Stats{}
	st.MemoryStats.Usage = 100 << 20
	srv.SetStats("c1", st)
	store, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	start(t, srv, Options{History: store, SampleInterval: time.Hour})
	deadline := time.Now().Add(2 * time.Second)
	for {
		samples, _ := store.MemorySamples(context.Background(), time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
		if len(samples["api"]) == 1 {
			if samples["api"][0].Used != 100<<20 || len(samples) != 1 {
				t.Fatalf("samples = %+v", samples)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no samples: %+v", samples)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if samples, _ := store.MemorySamples(context.Background(), time.Now().Add(-time.Minute), time.Now().Add(time.Minute)); len(samples["api"]) != 1 {
		t.Errorf("sampled more often than the interval: %d", len(samples["api"]))
	}
}
