// Package engine wires the docker client, detectors, actions, and the
// LLM stub together. It runs two loops side by side: a poll loop that
// feeds container snapshots to Detectors, and an event loop that feeds
// the daemon's event stream to EventDetectors.
package engine

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/llm"
)

const (
	logsTail       = 20
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
)

type Options struct {
	Detectors      []detector.Detector
	EventDetectors []detector.EventDetector
	Actions        []action.Action
	Classifier     llm.Classifier
	PollInterval   time.Duration
	// AlertCooldown suppresses repeat alerts from the same detector for
	// the same container name. Zero disables it.
	AlertCooldown     time.Duration
	ExcludeContainers []string
	// CollectStats fetches memory stats for running containers that
	// have a memory limit (one extra API call each per poll). Only
	// needed by the memory detector.
	CollectStats bool
}

type Engine struct {
	docker            *dockerclient.Client
	detectors         []detector.Detector
	eventDetectors    []detector.EventDetector
	actions           []action.Action
	classifier        llm.Classifier
	pollInterval      time.Duration
	cooldown          time.Duration
	excludeContainers map[string]struct{}
	collectStats      bool

	// Only touched by the poll loop.
	lastSeen map[string]struct{}

	// mu serializes dispatch (the poll and event loops both report
	// issues) and guards lastAlert.
	mu        sync.Mutex
	lastAlert map[string]time.Time // "detector/container name" -> when
	now       func() time.Time
}

func New(docker *dockerclient.Client, opts Options) *Engine {
	exclude := make(map[string]struct{}, len(opts.ExcludeContainers))
	for _, name := range opts.ExcludeContainers {
		exclude[name] = struct{}{}
	}
	classifier := opts.Classifier
	if classifier == nil {
		classifier = llm.NewNoopClassifier()
	}
	return &Engine{
		docker:            docker,
		detectors:         opts.Detectors,
		eventDetectors:    opts.EventDetectors,
		actions:           opts.Actions,
		classifier:        classifier,
		pollInterval:      opts.PollInterval,
		cooldown:          opts.AlertCooldown,
		excludeContainers: exclude,
		collectStats:      opts.CollectStats,
		lastSeen:          make(map[string]struct{}),
		lastAlert:         make(map[string]time.Time),
		now:               time.Now,
	}
}

// Run drives both loops until ctx is cancelled. Docker socket errors
// don't crash the daemon — they're logged, and each loop retries with
// exponential backoff.
func (e *Engine) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if len(e.eventDetectors) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runEvents(ctx)
		}()
	}
	e.runPoll(ctx)
	wg.Wait()
}

func (e *Engine) runPoll(ctx context.Context) {
	backoff := initialBackoff

	for {
		if ctx.Err() != nil {
			return
		}

		if err := e.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("poll failed, will retry", "error", err, "retry_in", backoff.String())
			if !sleep(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		backoff = initialBackoff
		if !sleep(ctx, e.pollInterval) {
			return
		}
	}
}

// runEvents keeps the event stream open. After a disconnect it resumes
// from the last event it processed, so events that happened while the
// stream was down are replayed instead of lost.
func (e *Engine) runEvents(ctx context.Context) {
	since := e.now()
	var last time.Time
	backoff := initialBackoff

	for {
		connectedAt := time.Now()
		err := e.docker.Events(ctx, since, detector.EventActions, func(ev dockerclient.Event) {
			t := time.Unix(0, ev.TimeNano)
			if !t.After(last) {
				return // replayed event we've already handled
			}
			last = t
			since = t
			e.handleEvent(ctx, ev, t)
		})
		if ctx.Err() != nil {
			return
		}

		if time.Since(connectedAt) > maxBackoff {
			backoff = initialBackoff
		}
		slog.Error("event stream failed, will reconnect", "error", err, "retry_in", backoff.String())
		if !sleep(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

func nextBackoff(b time.Duration) time.Duration {
	b *= 2
	if b > maxBackoff {
		b = maxBackoff
	}
	return b
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (e *Engine) pollOnce(ctx context.Context) error {
	if err := e.docker.Ping(ctx); err != nil {
		return err
	}

	summaries, err := e.docker.ListContainers(ctx)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(summaries))
	for _, summary := range summaries {
		seen[summary.ID] = struct{}{}

		name := containerName(summary)
		if _, excluded := e.excludeContainers[name]; excluded {
			continue
		}

		inspect, err := e.docker.InspectContainer(ctx, summary.ID)
		if err != nil {
			logContainerErr("inspect failed, skipping container this round", name, err)
			continue
		}

		snapshot := toSnapshot(name, inspect)
		if e.collectStats && inspect.State.Running && inspect.HostConfig.Memory > 0 {
			if stats, err := e.docker.ContainerStats(ctx, summary.ID); err != nil {
				logContainerErr("fetch stats failed", name, err)
			} else {
				snapshot.MemoryUsed = stats.MemoryUsed()
				snapshot.MemoryLimit = stats.MemoryStats.Limit
			}
		}

		var issues []*detector.Issue
		for _, d := range e.detectors {
			if issue := d.Check(snapshot); issue != nil {
				issues = append(issues, issue)
			}
		}
		e.report(ctx, summary.ID, inspect.Config.Tty, issues)
	}

	e.forgetGone(seen)
	return nil
}

// forgetGone drops detector state for containers that were present on
// the previous poll but have since been removed.
func (e *Engine) forgetGone(seen map[string]struct{}) {
	for id := range e.lastSeen {
		if _, ok := seen[id]; ok {
			continue
		}
		for _, d := range e.detectors {
			if f, ok := d.(detector.Forgetter); ok {
				f.Forget(id)
			}
		}
	}
	e.lastSeen = seen
}

func (e *Engine) handleEvent(ctx context.Context, ev dockerclient.Event, t time.Time) {
	name := strings.TrimPrefix(ev.Actor.Attributes["name"], "/")
	if _, excluded := e.excludeContainers[name]; excluded {
		return
	}

	cev := detector.ContainerEvent{
		ID:       ev.Actor.ID,
		Name:     name,
		Action:   ev.Action,
		ExitCode: eventExitCode(ev.Actor.Attributes),
		Time:     t,
	}

	var issues []*detector.Issue
	for _, d := range e.eventDetectors {
		if issue := d.HandleEvent(cev); issue != nil {
			issues = append(issues, issue)
		}
	}
	if len(issues) == 0 {
		return
	}

	// Fill in the rest of the container state. The container may already
	// be gone (docker run --rm); then the event data is all we have.
	tty := false
	if inspect, err := e.docker.InspectContainer(ctx, cev.ID); err == nil {
		tty = inspect.Config.Tty
		snap := toSnapshot(name, inspect)
		for _, issue := range issues {
			issue.Container = mergeSnapshot(issue.Container, snap)
		}
	}
	e.report(ctx, cev.ID, tty, issues)
}

// mergeSnapshot overlays what an event told us on top of inspect data:
// by the time we inspect, a restart policy may already have reset the
// exit code and OOM flag.
func mergeSnapshot(fromEvent, inspected detector.ContainerSnapshot) detector.ContainerSnapshot {
	if fromEvent.ExitCode != 0 {
		inspected.ExitCode = fromEvent.ExitCode
	}
	inspected.OOMKilled = inspected.OOMKilled || fromEvent.OOMKilled
	return inspected
}

// eventExitCode reads the exit code of a "die" event. Docker calls the
// attribute exitCode; Podman's compat API has used containerExitCode.
func eventExitCode(attrs map[string]string) int {
	for _, key := range []string{"exitCode", "containerExitCode"} {
		if v, ok := attrs[key]; ok {
			if code, err := strconv.Atoi(v); err == nil {
				return code
			}
		}
	}
	return 0
}

// report applies the cooldown, fetches logs once for all surviving
// issues, and dispatches them to every action and the classifier.
func (e *Engine) report(ctx context.Context, containerID string, tty bool, issues []*detector.Issue) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	var fresh []*detector.Issue
	for _, issue := range issues {
		key := issue.Detector + "/" + issue.Container.Name
		if last, ok := e.lastAlert[key]; ok && e.cooldown > 0 && now.Sub(last) < e.cooldown {
			slog.Debug("alert suppressed by cooldown", "detector", issue.Detector, "container", issue.Container.Name)
			continue
		}
		e.lastAlert[key] = now
		fresh = append(fresh, issue)
	}
	e.pruneAlerts(now)
	if len(fresh) == 0 {
		return
	}

	logs, err := e.docker.ContainerLogs(ctx, containerID, logsTail, tty)
	if err != nil {
		logContainerErr("fetch logs failed", fresh[0].Container.Name, err)
	}

	for _, issue := range fresh {
		issue.Logs = logs
		for _, a := range e.actions {
			if err := a.Run(ctx, *issue); err != nil {
				slog.Error("action failed", "action", a.Name(), "container", issue.Container.Name, "error", err)
			}
		}
		if err := e.classifier.Classify(ctx, *issue); err != nil {
			slog.Warn("llm classification failed", "container", issue.Container.Name, "error", err)
		}
	}
}

func (e *Engine) pruneAlerts(now time.Time) {
	for key, t := range e.lastAlert {
		if now.Sub(t) >= e.cooldown {
			delete(e.lastAlert, key)
		}
	}
}

// logContainerErr logs a per-container API error, at debug level if the
// container simply went away in the meantime.
func logContainerErr(msg, name string, err error) {
	if dockerclient.IsGone(err) {
		slog.Debug(msg+": container is gone", "container", name)
		return
	}
	slog.Warn(msg, "container", name, "error", err)
}

func containerName(s dockerclient.ContainerSummary) string {
	if len(s.Names) == 0 {
		return s.ID
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

func toSnapshot(name string, inspect *dockerclient.ContainerInspect) detector.ContainerSnapshot {
	snap := detector.ContainerSnapshot{
		ID:           inspect.ID,
		Name:         name,
		Status:       inspect.State.Status,
		RestartCount: inspect.RestartCount,
		ExitCode:     inspect.State.ExitCode,
		OOMKilled:    inspect.State.OOMKilled,
		StartedAt:    parseTime(inspect.State.StartedAt),
		FinishedAt:   parseTime(inspect.State.FinishedAt),
	}
	if h := inspect.State.Health; h != nil {
		snap.HealthStatus = h.Status
		snap.HealthFailingStreak = h.FailingStreak
		if len(h.Log) > 0 {
			snap.HealthLastOutput = h.Log[len(h.Log)-1].Output
		}
	}
	return snap
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
