package engine

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/dockertest"
)

type recorder struct {
	issues chan detector.Issue
}

func (r *recorder) Name() string { return "recorder" }

func (r *recorder) Run(_ context.Context, issue detector.Issue) error {
	r.issues <- issue
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
	rec := &recorder{issues: make(chan detector.Issue, 32)}
	opts.Actions = append(opts.Actions, rec)
	if opts.PollInterval == 0 {
		opts.PollInterval = 20 * time.Millisecond
	}
	eng := New(dockerclient.New(srv.SocketPath), opts)

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
	return rec
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
