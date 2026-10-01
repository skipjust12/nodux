package engine

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/dockertest"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
)

type recorder struct {
	issues chan detector.Issue
}

func (r *recorder) Name() string { return "recorder" }

func (r *recorder) Send(_ context.Context, n action.Notification) error {
	for _, issue := range n.Alerts {
		r.issues <- issue
	}
	return nil
}

func (r *recorder) next(t *testing.T) detector.Issue {
	t.Helper()
	select {
	case issue := <-r.issues:
		return issue
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for an issue")
		return detector.Issue{}
	}
}

func (r *recorder) none(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case issue := <-r.issues:
		t.Fatalf("unexpected issue: %s %s: %s", issue.Detector, issue.Container.Name, issue.Message)
	case <-time.After(wait):
	}
}

func container(id, name, status string) *dockerclient.ContainerInspect {
	c := &dockerclient.ContainerInspect{ID: id, Name: "/" + name}
	c.State.Status = status
	c.State.Running = status == "running"
	return c
}

func event(id, name, action string, attrs map[string]string, at time.Time) dockerclient.Event {
	a := map[string]string{"name": name}
	for k, v := range attrs {
		a[k] = v
	}
	return dockerclient.Event{Type: "container", Action: action, Actor: dockerclient.Actor{ID: id, Attributes: a}, TimeNano: at.UnixNano()}
}

func start(t *testing.T, srv *dockertest.Server, opts Options) *recorder {
	t.Helper()
	rec, _ := startEngine(t, srv, opts)
	return rec
}

func startEngine(t *testing.T, srv *dockertest.Server, opts Options) (*recorder, *Engine) {
	t.Helper()
	rec := &recorder{issues: make(chan detector.Issue, 32)}
	opts.Actions = append(opts.Actions, rec)
	if opts.PollInterval == 0 {
		opts.PollInterval = 20 * time.Millisecond
	}
	eng := New(dockerclient.New(srv.SocketPath), opts)
	eng.minBackoff = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		eng.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return rec, eng
}

func TestEngine_PollDetectorWithLogsAndExclude(t *testing.T) {
	srv := dockertest.New(t)
	sick := container("c1", "web", "running")
	sick.State.Health = &dockerclient.Health{Status: "unhealthy", FailingStreak: 4, Log: []dockerclient.HealthLog{{ExitCode: 1, Output: "connection refused"}}}
	srv.AddContainer(sick, "GET /health 500")
	ignored := container("c2", "noisy", "running")
	ignored.State.Health = &dockerclient.Health{Status: "unhealthy"}
	srv.AddContainer(ignored)

	rec := start(t, srv, Options{
		Detectors:         []detector.Detector{detector.NewUnhealthyDetector()},
		ExcludeContainers: []string{"noisy"},
	})

	issue := rec.next(t)
	if issue.Detector != "unhealthy" || issue.Container.Name != "web" {
		t.Fatalf("unexpected issue: %+v", issue)
	}
	if !strings.Contains(issue.Message, "connection refused") || issue.Container.HealthFailingStreak != 4 {
		t.Errorf("health details missing: %+v", issue)
	}
	if len(issue.Logs) != 1 || issue.Logs[0] != "GET /health 500" {
		t.Errorf("logs = %q", issue.Logs)
	}
	rec.none(t, 150*time.Millisecond) // excluded container and no repeats
}

func TestEngine_MemoryStatsOnlyForLimitedRunningContainers(t *testing.T) {
	srv := dockertest.New(t)

	limited := container("m1", "cache", "running")
	limited.HostConfig.Memory = 256 << 20
	srv.AddContainer(limited)
	st := &dockerclient.Stats{}
	st.MemoryStats.Usage = 250 << 20
	st.MemoryStats.Limit = 256 << 20
	st.MemoryStats.Stats = map[string]uint64{"total_inactive_file": 5 << 20}
	srv.SetStats("m1", st)

	srv.AddContainer(container("u1", "unlimited", "running"))
	stopped := container("s1", "stopped", "exited")
	stopped.HostConfig.Memory = 256 << 20
	srv.AddContainer(stopped)

	rec := start(t, srv, Options{
		Detectors:    []detector.Detector{detector.NewMemoryDetector(90, 0)},
		CollectStats: true,
	})

	issue := rec.next(t)
	if issue.Detector != "memory" || issue.Container.Name != "cache" {
		t.Fatalf("unexpected issue: %+v", issue)
	}
	if issue.Container.MemoryUsed != 245<<20 || !strings.Contains(issue.Message, "96% of limit") {
		t.Errorf("usage not computed from stats: used=%d msg=%q", issue.Container.MemoryUsed, issue.Message)
	}
	rec.none(t, 100*time.Millisecond)

	if srv.StatsCallCount("u1") != 0 || srv.StatsCallCount("s1") != 0 {
		t.Errorf("stats fetched for unlimited/stopped containers: u1=%d s1=%d", srv.StatsCallCount("u1"), srv.StatsCallCount("s1"))
	}
}

func TestEngine_NoStatsWhenNotRequested(t *testing.T) {
	srv := dockertest.New(t)
	limited := container("m1", "cache", "running")
	limited.HostConfig.Memory = 256 << 20
	srv.AddContainer(limited)

	start(t, srv, Options{Detectors: []detector.Detector{detector.NewUnhealthyDetector()}})
	time.Sleep(100 * time.Millisecond)
	if n := srv.StatsCallCount("m1"); n != 0 {
		t.Fatalf("stats fetched %d times with CollectStats off", n)
	}
}

func TestEngine_EventDetectorsAndCooldown(t *testing.T) {
	srv := dockertest.New(t)
	srv.AddContainer(container("w1", "worker", "exited"), "panic: nil map")
	srv.AddContainer(container("m1", "hog", "running"))
	stream := srv.NewStream()

	rec := start(t, srv, Options{
		EventDetectors: []detector.EventDetector{
			detector.NewOOMDetector(),
			detector.NewExitDetector([]int{0}, true),
		},
		AlertCooldown:     time.Hour,
		ExcludeContainers: []string{"ignored"},
	})

	now := time.Now()
	tick := func() time.Time { now = now.Add(time.Millisecond); return now }

	// Crash: reported with the exit code from the event and the logs.
	stream <- event("w1", "worker", "start", nil, tick())
	stream <- event("w1", "worker", "die", map[string]string{"exitCode": "2"}, tick())
	issue := rec.next(t)
	if issue.Detector != "exit" || issue.Container.Name != "worker" || issue.Container.ExitCode != 2 {
		t.Fatalf("unexpected issue: %+v", issue)
	}
	if issue.Container.Status != "exited" || len(issue.Logs) != 1 {
		t.Errorf("not enriched from inspect/logs: %+v", issue)
	}

	// OOM: one oom issue, the follow-up die is not double-reported.
	stream <- event("m1", "hog", "oom", nil, tick())
	stream <- event("m1", "hog", "die", map[string]string{"exitCode": "137"}, tick())
	issue = rec.next(t)
	if issue.Detector != "oom" || !issue.Container.OOMKilled {
		t.Fatalf("unexpected issue: %+v", issue)
	}

	// Same crash again: within cooldown. A manual stop: never reported.
	// An excluded container: never reported. A container removed with
	// --rm before we could inspect it: still reported, from event data.
	stream <- event("w1", "worker", "start", nil, tick())
	stream <- event("w1", "worker", "die", map[string]string{"exitCode": "2"}, tick())
	stream <- event("w1", "worker", "start", nil, tick())
	stream <- event("w1", "worker", "kill", map[string]string{"signal": "15"}, tick())
	stream <- event("w1", "worker", "die", map[string]string{"exitCode": "143"}, tick())
	stream <- event("x1", "ignored", "die", map[string]string{"exitCode": "1"}, tick())
	stream <- event("gone", "oneshot", "die", map[string]string{"exitCode": "1"}, tick())

	issue = rec.next(t)
	if issue.Container.Name != "oneshot" || issue.Container.ExitCode != 1 {
		t.Fatalf("unexpected issue: %+v", issue)
	}
	rec.none(t, 150*time.Millisecond)
}

func TestEngine_EventStreamResumesWithoutDuplicates(t *testing.T) {
	srv := dockertest.New(t)
	first := srv.NewStream()

	rec := start(t, srv, Options{
		EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)},
	})

	t0 := time.Now()
	crash := event("a", "api", "die", map[string]string{"exitCode": "1"}, t0)
	first <- crash
	if issue := rec.next(t); issue.Container.Name != "api" {
		t.Fatalf("unexpected issue: %+v", issue)
	}
	<-srv.EventQueries // initial connect

	// Daemon drops the stream; on reconnect it replays from `since`,
	// which includes the event we already handled.
	second := srv.NewStream()
	close(first)

	q, _ := url.ParseQuery(<-srv.EventQueries)
	if want := time.Unix(0, crash.TimeNano); q.Get("since") != formatSince(want) {
		t.Fatalf("reconnect since = %q, want %q", q.Get("since"), formatSince(want))
	}

	second <- crash
	second <- event("b", "db", "die", map[string]string{"exitCode": "1"}, t0.Add(time.Second))
	if issue := rec.next(t); issue.Container.Name != "db" {
		t.Fatalf("expected only the new event, got %+v", issue)
	}
	rec.none(t, 100*time.Millisecond)
}

func formatSince(t time.Time) string {
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}

func TestEngine_LevelAlertResolvesAndRemovedContainerCloses(t *testing.T) {
	srv := dockertest.New(t)
	web := container("c1", "web", "running")
	web.State.Health = &dockerclient.Health{Status: "unhealthy", FailingStreak: 3}
	srv.AddContainer(web, "boom")
	db := container("c2", "db", "running")
	db.State.Health = &dockerclient.Health{Status: "unhealthy"}
	srv.AddContainer(db)

	rec := start(t, srv, Options{Detectors: []detector.Detector{detector.NewUnhealthyDetector()}, Hostname: "vps1"})

	got := map[string]detector.Issue{}
	for i := 0; i < 2; i++ {
		issue := rec.next(t)
		got[issue.Container.Name] = issue
	}
	if w := got["web"]; w.Resolved || w.Host != "vps1" || len(w.Logs) != 1 {
		t.Fatalf("unexpected alert: %+v", w)
	}
	rec.none(t, 100*time.Millisecond) // one alert per episode

	healthy := container("c1", "web", "running")
	healthy.State.Health = &dockerclient.Health{Status: "healthy"}
	srv.AddContainer(healthy)
	issue := rec.next(t)
	if !issue.Resolved || issue.Container.Name != "web" || !strings.HasPrefix(issue.Message, "resolved after") ||
		!strings.Contains(issue.Message, "(was: healthcheck failing (3 consecutive failures))") {
		t.Fatalf("unexpected resolution: %+v", issue)
	}
	if issue.Container.HealthStatus != "healthy" || issue.Logs != nil {
		t.Errorf("resolution should carry the current state and no logs: %+v", issue)
	}

	srv.RemoveContainer("c2")
	issue = rec.next(t)
	if !issue.Resolved || issue.Container.Name != "db" || !strings.HasPrefix(issue.Message, "container removed after") {
		t.Fatalf("unexpected resolution: %+v", issue)
	}
	rec.none(t, 100*time.Millisecond)
}

func TestEngine_CrashLoopFromEventsResolvesOnPoll(t *testing.T) {
	srv := dockertest.New(t)
	srv.AddContainer(container("c1", "flaky", "restarting"), "exit 1")
	stream := srv.NewStream()

	cl := detector.NewCrashLoopDetector(2, 150*time.Millisecond)
	rec := start(t, srv, Options{
		Detectors:      []detector.Detector{cl},
		EventDetectors: []detector.EventDetector{cl},
	})

	now := time.Now()
	for i := 0; i < 2; i++ {
		stream <- event("c1", "flaky", "die", map[string]string{"exitCode": "1"}, now.Add(time.Duration(2*i)*time.Millisecond))
		stream <- event("c1", "flaky", "start", nil, now.Add(time.Duration(2*i+1)*time.Millisecond))
	}
	issue := rec.next(t)
	if issue.Detector != "crashloop" || issue.Resolved || issue.Container.Status != "restarting" || len(issue.Logs) != 1 {
		t.Fatalf("unexpected alert: %+v", issue)
	}

	// Still restarting after the window: the episode stays open...
	rec.none(t, 250*time.Millisecond)
	// ...until it runs without restarts.
	srv.AddContainer(container("c1", "flaky", "running"))
	issue = rec.next(t)
	if !issue.Resolved || issue.Detector != "crashloop" || issue.Container.Status != "running" {
		t.Fatalf("unexpected resolution: %+v", issue)
	}
}

func TestEngine_ReloadSignalDoesNotHideCrash(t *testing.T) {
	srv := dockertest.New(t)
	nginx := container("n1", "nginx", "running")
	nginx.Config.StopSignal = "SIGQUIT"
	srv.AddContainer(nginx)
	stream := srv.NewStream()

	rec := start(t, srv, Options{EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)}})

	now := time.Now()
	stream <- event("n1", "nginx", "kill", map[string]string{"signal": "1"}, now)
	stream <- event("n1", "nginx", "die", map[string]string{"exitCode": "1"}, now.Add(time.Millisecond))
	if issue := rec.next(t); issue.Detector != "exit" || issue.Container.ExitCode != 1 {
		t.Fatalf("unexpected issue: %+v", issue)
	}

	// docker stop sends the image's stop signal: not a crash.
	stream <- event("n1", "nginx", "start", nil, now.Add(2*time.Millisecond))
	stream <- event("n1", "nginx", "kill", map[string]string{"signal": "3"}, now.Add(3*time.Millisecond))
	stream <- event("n1", "nginx", "die", map[string]string{"exitCode": "1"}, now.Add(4*time.Millisecond))
	rec.none(t, 100*time.Millisecond)
}

func TestEngine_EventsWithSameTimestampAreAllHandled(t *testing.T) {
	srv := dockertest.New(t)
	stream := srv.NewStream()
	rec := start(t, srv, Options{EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)}})

	now := time.Now()
	stream <- event("a", "api", "die", map[string]string{"exitCode": "1"}, now)
	stream <- event("b", "db", "die", map[string]string{"exitCode": "1"}, now)
	names := map[string]bool{rec.next(t).Container.Name: true, rec.next(t).Container.Name: true}
	if !names["api"] || !names["db"] {
		t.Fatalf("got %v", names)
	}
}

func TestEngine_DockerDownAlertAndRecovery(t *testing.T) {
	srv := dockertest.New(t)
	srv.SetDown(true)
	rec, eng := startEngine(t, srv, Options{DockerDownAfter: 30 * time.Millisecond})

	issue := rec.next(t)
	if issue.Detector != "docker" || issue.Severity != detector.SeverityCritical || issue.Resolved ||
		!strings.Contains(issue.Message, "docker daemon unreachable for") {
		t.Fatalf("unexpected issue: %+v", issue)
	}
	if eng.Healthy() {
		t.Error("engine reports healthy while the daemon is down")
	}
	rec.none(t, 100*time.Millisecond)

	srv.SetDown(false)
	issue = rec.next(t)
	if issue.Detector != "docker" || !issue.Resolved {
		t.Fatalf("unexpected resolution: %+v", issue)
	}
	if !eng.Healthy() {
		t.Error("engine not healthy after recovery")
	}
}

type fakeHost struct {
	mu     sync.Mutex
	issues []*detector.Issue
}

func (f *fakeHost) Name() string { return "host_disk" }

func (f *fakeHost) Check() []*detector.Issue {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*detector.Issue
	for _, i := range f.issues {
		c := *i
		out = append(out, &c)
	}
	return out
}

func (f *fakeHost) set(issues ...*detector.Issue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues = issues
}

func TestEngine_HostDetectorsRunEvenWhenDockerIsDown(t *testing.T) {
	srv := dockertest.New(t)
	srv.SetDown(true)
	host := &fakeHost{}
	host.set(
		&detector.Issue{Detector: "host_disk", Severity: "critical", Message: "disk / at 95%", Resource: "/"},
		&detector.Issue{Detector: "host_disk", Severity: "critical", Message: "disk /data at 99%", Resource: "/data"},
	)
	rec := start(t, srv, Options{HostDetectors: []detector.HostDetector{host}})

	got := map[string]bool{rec.next(t).Resource: true, rec.next(t).Resource: true}
	if !got["/"] || !got["/data"] {
		t.Fatalf("got %v", got)
	}
	rec.none(t, 100*time.Millisecond)

	host.set(&detector.Issue{Detector: "host_disk", Severity: "critical", Message: "disk /data at 99%", Resource: "/data"})
	issue := rec.next(t)
	if !issue.Resolved || issue.Resource != "/" || !strings.Contains(issue.Message, "(was: disk / at 95%)") {
		t.Fatalf("unexpected resolution: %+v", issue)
	}
}

func TestEngine_ExpectedContainers(t *testing.T) {
	srv := dockertest.New(t)
	srv.AddContainer(container("c1", "api", "exited"), "shutting down")
	rec := start(t, srv, Options{Expected: detector.NewExpectedDetector([]string{"api", "db"}, 0)})

	got := map[string]detector.Issue{}
	for i := 0; i < 2; i++ {
		issue := rec.next(t)
		got[issue.Container.Name] = issue
	}
	if api := got["api"]; api.Container.ID != "c1" || len(api.Logs) != 1 || !strings.Contains(api.Message, "status: exited") {
		t.Errorf("api: %+v", api)
	}
	if db := got["db"]; !strings.Contains(db.Message, "does not exist") {
		t.Errorf("db: %+v", db)
	}

	srv.AddContainer(container("c1", "api", "running"))
	issue := rec.next(t)
	if !issue.Resolved || issue.Container.Name != "api" {
		t.Fatalf("unexpected resolution: %+v", issue)
	}
	rec.none(t, 100*time.Millisecond)
}

type fakeAnalyzer struct {
	seen chan llm.Incident
}

func (f *fakeAnalyzer) Analyze(_ context.Context, inc llm.Incident) (string, error) {
	f.seen <- inc
	return "the database is down", nil
}

func TestEngine_RedactsBeforeClassifyingAndSending(t *testing.T) {
	srv := dockertest.New(t)
	srv.AddContainer(container("w1", "worker", "exited"), "connecting with password=hunter2", strings.Repeat("x", 5000))
	stream := srv.NewStream()

	red, err := redact.New(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	cls := &fakeAnalyzer{seen: make(chan llm.Incident, 4)}
	rec := start(t, srv, Options{
		EventDetectors: []detector.EventDetector{detector.NewExitDetector([]int{0}, true)},
		Redactor:       red,
		Analyzer:       cls,
	})

	stream <- event("w1", "worker", "die", map[string]string{"exitCode": "1"}, time.Now())
	issue := rec.next(t)
	classified := (<-cls.seen).Alerts[0]

	for _, is := range []detector.Issue{issue, classified} {
		if len(is.Logs) != 2 || is.Logs[0] != "connecting with password=[REDACTED]" {
			t.Errorf("logs not redacted: %q", is.Logs)
		}
		if len(is.Logs[1]) > maxLogLine+10 {
			t.Errorf("long log line not truncated: %d bytes", len(is.Logs[1]))
		}
	}
	if issue.Analysis != "the database is down" {
		t.Errorf("analysis = %q", issue.Analysis)
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second: "45s", 12*time.Minute + 20*time.Second: "12m",
		3*time.Hour + 5*time.Minute: "3h5m", 2 * time.Hour: "2h",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
