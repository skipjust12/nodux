// Package engine wires the docker client, detectors, actions, and the
// LLM layer together. It runs two loops side by side: a poll loop that
// checks the host and feeds container snapshots to Detectors, and an
// event loop that feeds the daemon's event stream to EventDetectors.
// Alerts go out through a dispatcher goroutine that groups them into
// incidents and runs the LLM layer, so neither can hold up detection.
// With a state file, open alerts, detector state and the event stream
// position survive a restart.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/incident"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
	"github.com/skipjust12/nodux/internal/state"
)

const (
	logsTail       = 20
	maxLogLine     = 1000 // bytes; a single huge line shouldn't bloat every payload
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second

	queueSize = 256

	dockerDetector = "docker"
)

type Options struct {
	Detectors      []detector.Detector
	EventDetectors []detector.EventDetector
	HostDetectors  []detector.HostDetector
	Expected       *detector.ExpectedDetector
	Actions        []action.Action
	// Grouping groups related alerts into incidents; its zero value
	// sends every alert on its own, right away.
	Grouping incident.Config
	// Analyzer annotates incidents with a probable cause. nil disables it.
	Analyzer llm.Analyzer
	// Redactor scrubs messages and logs before they leave the host (and
	// before they reach the analyzer). nil disables it.
	Redactor *redact.Redactor
	// State keeps open alerts, detector state and the event stream
	// position across restarts. nil keeps them in memory only.
	State *state.File
	// History records every alert sent and, every SampleInterval, the
	// memory use of each running container. nil disables both.
	History        *history.Store
	SampleInterval time.Duration
	// Hostname is stamped on every alert.
	Hostname     string
	PollInterval time.Duration
	// AlertCooldown suppresses repeats of one-off event alerts (exit,
	// oom) from the same detector for the same container name. Level
	// alerts don't need it: they fire once per episode. Zero disables it.
	AlertCooldown time.Duration
	// DockerDownAfter is how long the daemon has to be unreachable
	// before that's an alert. Zero disables the alert.
	DockerDownAfter   time.Duration
	ExcludeContainers []string
	// CollectStats fetches memory stats for running containers that
	// have a memory limit (one extra API call each per poll). Only
	// needed by the memory detector.
	CollectStats bool
}

type Engine struct {
	docker *dockerclient.Client
	opts   Options
	// First retry delay after a Docker API failure; overridable for tests.
	minBackoff time.Duration

	excludeContainers map[string]struct{}
	// Detectors that implement both interfaces (crashloop): their event
	// issues open level-triggered episodes instead of one-off alerts.
	levelEvents map[string]bool
	stateful    []detector.Stateful
	grouper     *incident.Grouper

	// Only touched by the poll loop.
	lastSeen     map[string]struct{}
	nextSample   time.Time
	saveFailing  bool
	imagesPruned time.Time

	// eventMu is held while the event loop handles an event, and by
	// saveState, which needs the event detectors and the stream position
	// to agree. It guards evSince, evLast and evHandled.
	eventMu   sync.Mutex
	evSince   time.Time       // where to resume the stream
	evLast    time.Time       // timestamp of the last event handled
	evHandled map[string]bool // events at evLast already handled

	// mu guards everything below; the poll loop, the event loop and the
	// dispatcher all touch it.
	mu        sync.Mutex
	lastAlert map[string]time.Time // "detector/container name" -> when
	active    map[string]*activeAlert
	images    map[string]*imageInfo        // by container name
	labels    map[string]map[string]string // by container ID, from polls, for events without labels
	starts    map[string]time.Time         // last "start" by container ID
	lastRuns  map[string]time.Duration     // how long the last run lasted, by container ID
	now       func() time.Time

	healthy atomic.Bool
	queue   chan detector.Issue
}

// activeAlert is an open level-triggered episode.
type activeAlert struct {
	issue       detector.Issue
	since       time.Time
	containerID string // for resolving when the container goes away
}

// imageInfo tracks which image a container name runs, so the LLM layer
// can tell a crash right after a deploy from one out of the blue.
type imageInfo struct {
	Image     string    `json:"image"`    // as configured: api:latest
	ImageID   string    `json:"image_id"` // sha256:...
	Since     time.Time `json:"since"`    // first seen running it
	Prev      string    `json:"prev,omitempty"`
	ChangedAt time.Time `json:"changed_at,omitempty"`
	LastSeen  time.Time `json:"last_seen"` // day granularity, for pruning
}

func New(docker *dockerclient.Client, opts Options) *Engine {
	exclude := make(map[string]struct{}, len(opts.ExcludeContainers))
	for _, name := range opts.ExcludeContainers {
		exclude[name] = struct{}{}
	}
	levelEvents := make(map[string]bool)
	for _, d := range opts.EventDetectors {
		if _, ok := d.(detector.Detector); ok {
			levelEvents[d.Name()] = true
		}
	}
	e := &Engine{
		docker:            docker,
		opts:              opts,
		minBackoff:        initialBackoff,
		excludeContainers: exclude,
		levelEvents:       levelEvents,
		grouper:           incident.New(opts.Grouping),
		lastSeen:          make(map[string]struct{}),
		evHandled:         make(map[string]bool),
		lastAlert:         make(map[string]time.Time),
		active:            make(map[string]*activeAlert),
		images:            make(map[string]*imageInfo),
		labels:            make(map[string]map[string]string),
		starts:            make(map[string]time.Time),
		lastRuns:          make(map[string]time.Duration),
		now:               time.Now,
		queue:             make(chan detector.Issue, queueSize),
	}
	e.stateful = collectStateful(opts)
	return e
}

func collectStateful(opts Options) []detector.Stateful {
	var out []detector.Stateful
	seen := make(map[string]bool)
	add := func(d any) {
		if s, ok := d.(detector.Stateful); ok && !seen[s.Name()] {
			seen[s.Name()] = true
			out = append(out, s)
		}
	}
	for _, d := range opts.Detectors {
		add(d)
	}
	for _, d := range opts.EventDetectors {
		add(d)
	}
	for _, d := range opts.HostDetectors {
		add(d)
	}
	if opts.Expected != nil {
		add(opts.Expected)
	}
	return out
}

// Healthy reports whether the last poll of the Docker daemon worked.
// The heartbeat only pings while it does.
func (e *Engine) Healthy() bool { return e.healthy.Load() }

// ActiveAlerts returns the open alerts, oldest first, each with
// DetectedAt set to when it started.
func (e *Engine) ActiveAlerts() []detector.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]detector.Issue, 0, len(e.active))
	for _, a := range e.active {
		issue := a.issue
		issue.DetectedAt = a.since
		issue.Logs = nil
		issue.Message = e.opts.Redactor.String(issue.Message)
		out = append(out, issue)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DetectedAt.Before(out[j].DetectedAt) })
	return out
}

// Run drives both loops until ctx is cancelled, then delivers whatever
// alerts are still queued and saves the state one last time. Docker
// socket errors don't crash the daemon: they're logged, and each loop
// retries with exponential backoff.
func (e *Engine) Run(ctx context.Context) {
	e.restore()

	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		e.dispatch(ctx)
	}()

	var wg sync.WaitGroup
	if len(e.opts.EventDetectors) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runEvents(ctx)
		}()
	}
	e.runPoll(ctx)
	wg.Wait()

	close(e.queue)
	<-dispatched
	e.saveState()
}

func (e *Engine) runPoll(ctx context.Context) {
	backoff := e.minBackoff
	var downSince time.Time

	for {
		if ctx.Err() != nil {
			return
		}
		e.checkHost(ctx)

		if err := e.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			e.healthy.Store(false)
			if downSince.IsZero() {
				downSince = e.now()
			}
			e.dockerDown(ctx, downSince, err)
			e.saveState()
			slog.Error("poll failed, will retry", "error", err, "retry_in", backoff.String())
			if !sleep(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		e.healthy.Store(true)
		downSince = time.Time{}
		// Also resolves a daemon outage that started before a restart.
		e.dockerUp(ctx)
		e.saveState()
		backoff = e.minBackoff
		if !sleep(ctx, e.opts.PollInterval) {
			return
		}
	}
}

// runEvents keeps the event stream open. After a disconnect, or a
// restart of nodux, it resumes from the last event it handled, so
// events that happened in between are replayed instead of lost.
func (e *Engine) runEvents(ctx context.Context) {
	backoff := e.minBackoff
	for {
		e.eventMu.Lock()
		since := e.evSince
		e.eventMu.Unlock()

		connectedAt := time.Now()
		err := e.docker.Events(ctx, since, detector.EventActions, func(ev dockerclient.Event) {
			e.eventMu.Lock()
			defer e.eventMu.Unlock()
			// The daemon replays everything from `since` inclusive, and
			// distinct events can share a timestamp, so remember which ones
			// at the last timestamp were already handled.
			t := time.Unix(0, ev.TimeNano)
			key := ev.Action + "/" + ev.Actor.ID
			switch {
			case t.Before(e.evLast):
				return
			case t.Equal(e.evLast):
				if e.evHandled[key] {
					return
				}
			default:
				e.evLast = t
				clear(e.evHandled)
			}
			e.evHandled[key] = true
			e.evSince = t
			e.handleEvent(ctx, ev, t)
		})
		if ctx.Err() != nil {
			return
		}

		if time.Since(connectedAt) > maxBackoff {
			backoff = e.minBackoff
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
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (e *Engine) checkHost(ctx context.Context) {
	for _, d := range e.opts.HostDetectors {
		out := e.trackSet(d.Name(), d.Check(), func(i *detector.Issue) string { return i.Resource })
		e.report(ctx, "", false, out)
	}
}

func (e *Engine) dockerDown(ctx context.Context, since time.Time, err error) {
	if e.opts.DockerDownAfter <= 0 {
		return
	}
	down := e.now().Sub(since)
	if down < e.opts.DockerDownAfter {
		return
	}
	issue := &detector.Issue{
		Detector:   dockerDetector,
		Severity:   detector.SeverityCritical,
		Message:    fmt.Sprintf("docker daemon unreachable for %s: %v", formatDuration(down), err),
		Resource:   "daemon",
		DetectedAt: e.now(),
	}
	if out := e.track(dockerDetector+"/daemon", issue, nil); out != nil {
		e.report(ctx, "", false, []*detector.Issue{out})
	}
}

func (e *Engine) dockerUp(ctx context.Context) {
	if out := e.track(dockerDetector+"/daemon", nil, nil); out != nil {
		e.report(ctx, "", false, []*detector.Issue{out})
	}
}

func (e *Engine) excluded(name string, labels map[string]string) bool {
	_, excluded := e.excludeContainers[name]
	return excluded || detector.Excluded(labels)
}

func (e *Engine) pollOnce(ctx context.Context) error {
	if err := e.docker.Ping(ctx); err != nil {
		return err
	}

	summaries, err := e.docker.ListContainers(ctx)
	if err != nil {
		return err
	}

	now := e.now()
	sample := e.opts.History != nil && e.opts.SampleInterval > 0 && !now.Before(e.nextSample)
	var samples []history.MemorySample

	seen := make(map[string]struct{}, len(summaries))
	statuses := make(map[string]string, len(summaries))
	ids := make(map[string]string, len(summaries))
	var labeledExpected []string
	for _, summary := range summaries {
		seen[summary.ID] = struct{}{}

		name := containerName(summary)
		statuses[name] = summary.State
		ids[name] = summary.ID
		labels := detector.RelevantLabels(summary.Labels)
		e.mu.Lock()
		e.labels[summary.ID] = labels
		e.mu.Unlock()
		if e.excluded(name, labels) {
			continue
		}
		e.noteImage(name, summary, now)
		if detector.ExpectedByLabel(labels) {
			labeledExpected = append(labeledExpected, name)
		}
		if len(e.opts.Detectors) == 0 && !sample {
			continue
		}

		inspect, err := e.docker.InspectContainer(ctx, summary.ID)
		if err != nil {
			logContainerErr("inspect failed, skipping container this round", name, err)
			continue
		}

		snapshot := toSnapshot(name, inspect)
		running := inspect.State.Running
		var stats *dockerclient.Stats
		if running && ((e.opts.CollectStats && inspect.HostConfig.Memory > 0) || sample) {
			if stats, err = e.docker.ContainerStats(ctx, summary.ID); err != nil {
				logContainerErr("fetch stats failed", name, err)
				stats = nil
			}
		}
		if stats != nil {
			if e.opts.CollectStats && inspect.HostConfig.Memory > 0 {
				snapshot.MemoryUsed = stats.MemoryUsed()
				snapshot.MemoryLimit = stats.MemoryStats.Limit
			}
			if sample {
				samples = append(samples, history.MemorySample{Time: now, Container: name, Used: stats.MemoryUsed(), Limit: snapshot.MemoryMax})
			}
		}

		var out []*detector.Issue
		for _, d := range e.opts.Detectors {
			var issue *detector.Issue
			if detector.Enabled(snapshot.Labels, d.Name()) {
				issue = d.Check(snapshot)
			}
			if o := e.track(d.Name()+"/"+summary.ID, issue, &snapshot); o != nil {
				out = append(out, o)
			}
		}
		e.report(ctx, summary.ID, inspect.Config.Tty, out)
	}

	if e.opts.Expected != nil {
		out := e.trackSet(e.opts.Expected.Name(), e.opts.Expected.Check(statuses, labeledExpected), func(i *detector.Issue) string { return i.Container.Name })
		for _, issue := range out {
			// An existing but stopped container has logs worth seeing.
			id := ids[issue.Container.Name]
			if !issue.Resolved {
				issue.Container.ID = id
			}
			e.report(ctx, id, false, []*detector.Issue{issue})
		}
	}

	if sample {
		e.nextSample = now.Add(e.opts.SampleInterval)
		if err := e.opts.History.AddMemorySamples(ctx, samples); err != nil {
			slog.Warn("recording memory samples failed", "error", err)
		}
	}
	e.forgetGone(ctx, seen)
	e.pruneImages(now)
	return nil
}

// noteImage records the image a container runs, and when that changed.
func (e *Engine) noteImage(name string, c dockerclient.ContainerSummary, now time.Time) {
	if c.ImageID == "" {
		return
	}
	day := now.UTC().Truncate(24 * time.Hour)
	e.mu.Lock()
	defer e.mu.Unlock()
	cur := e.images[name]
	switch {
	case cur == nil:
		e.images[name] = &imageInfo{Image: c.Image, ImageID: c.ImageID, Since: now, LastSeen: day}
	case cur.ImageID != c.ImageID:
		// A redeploy recreates the container: its creation time is when
		// the new image went in. Otherwise (a restart policy picking up a
		// retagged image) all we know is "by now".
		changed := now
		if created := time.Unix(c.Created, 0); c.Created > 0 && created.After(cur.Since) && created.Before(now) {
			changed = created
		}
		e.images[name] = &imageInfo{
			Image: c.Image, ImageID: c.ImageID, Since: changed, LastSeen: day,
			Prev:      fmt.Sprintf("%s (%s)", cur.Image, shortID(cur.ImageID)),
			ChangedAt: changed,
		}
	default:
		cur.LastSeen = day
	}
}

// pruneImages forgets container names not seen for a week, at most once
// a day: docker run without --name makes up a new one every time.
func (e *Engine) pruneImages(now time.Time) {
	if now.Sub(e.imagesPruned) < 24*time.Hour {
		return
	}
	e.imagesPruned = now
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, img := range e.images {
		if now.Sub(img.LastSeen) > 7*24*time.Hour {
			delete(e.images, name)
		}
	}
}

// forgetGone drops detector state for containers that were present on
// the previous poll (or had alerts open when nodux last stopped) but
// have since been removed, and closes their open episodes.
func (e *Engine) forgetGone(ctx context.Context, seen map[string]struct{}) {
	for id := range e.lastSeen {
		if _, ok := seen[id]; ok {
			continue
		}
		for _, d := range e.opts.Detectors {
			if f, ok := d.(detector.Forgetter); ok {
				f.Forget(id)
			}
		}
		e.forgetContainer(id)
		e.report(ctx, "", false, e.resolveContainer(id))
	}
	e.lastSeen = seen
}

func (e *Engine) forgetContainer(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.labels, id)
	delete(e.starts, id)
	delete(e.lastRuns, id)
}

func (e *Engine) handleEvent(ctx context.Context, ev dockerclient.Event, t time.Time) {
	name := strings.TrimPrefix(ev.Actor.Attributes["name"], "/")
	labels := detector.RelevantLabels(ev.Actor.Attributes)
	if len(labels) == 0 {
		// Podman doesn't put labels in event attributes; the last poll saw them.
		e.mu.Lock()
		labels = e.labels[ev.Actor.ID]
		e.mu.Unlock()
	}
	if e.excluded(name, labels) {
		return
	}

	cev := detector.ContainerEvent{
		ID:       ev.Actor.ID,
		Name:     name,
		Action:   ev.Action,
		ExitCode: eventExitCode(ev.Actor.Attributes),
		Signal:   detector.ParseSignal(ev.Actor.Attributes["signal"]),
		Time:     t,
		Labels:   labels,
	}
	if cev.Action == "kill" {
		// Needed to tell docker stop (the configured stop signal) from
		// docker kill -s HUP. The container is still alive at this point.
		if inspect, err := e.docker.InspectContainer(ctx, cev.ID); err == nil {
			cev.StopSignal = detector.ParseSignal(inspect.Config.StopSignal)
			if cev.StopSignal == 0 {
				cev.StopSignal = 15
			}
		}
	}
	e.noteRun(cev)

	var issues []*detector.Issue
	for _, d := range e.opts.EventDetectors {
		if !detector.Enabled(labels, d.Name()) {
			continue
		}
		issue := d.HandleEvent(cev)
		if issue == nil {
			continue
		}
		if e.levelEvents[d.Name()] {
			if o := e.track(d.Name()+"/"+cev.ID, issue, nil); o != nil {
				issues = append(issues, o)
			}
		} else if !e.coolingDown(issue) {
			issues = append(issues, issue)
		}
	}

	if len(issues) > 0 {
		// Fill in the rest of the container state. The container may
		// already be gone (docker run --rm); then the event data is all
		// we have.
		tty := false
		if inspect, err := e.docker.InspectContainer(ctx, cev.ID); err == nil {
			tty = inspect.Config.Tty
			snap := toSnapshot(name, inspect)
			if (cev.Action == "die" || cev.Action == "oom") && !snap.StartedAt.IsZero() && snap.StartedAt.Before(t) {
				// The run that just ended, if nodux missed its start.
				e.mu.Lock()
				if _, ok := e.lastRuns[cev.ID]; !ok {
					e.lastRuns[cev.ID] = t.Sub(snap.StartedAt)
				}
				e.mu.Unlock()
			}
			for _, issue := range issues {
				issue.Container = mergeSnapshot(issue.Container, snap)
			}
		}
		e.mu.Lock()
		lastRun := e.lastRuns[cev.ID]
		e.mu.Unlock()
		for _, issue := range issues {
			if !issue.Resolved {
				issue.Container.LastRun = lastRun
			}
		}
		e.report(ctx, cev.ID, tty, issues)
	}

	if cev.Action == "destroy" {
		e.forgetContainer(cev.ID)
		e.report(ctx, "", false, e.resolveContainer(cev.ID))
	}
}

// noteRun keeps track of how long each run of a container lasts: "died
// 2s after starting" and "died after 3 days" are different problems.
func (e *Engine) noteRun(ev detector.ContainerEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch ev.Action {
	case "start":
		e.starts[ev.ID] = ev.Time
	case "oom", "die":
		// An OOM kill comes just before its die; either ends the run.
		if s, ok := e.starts[ev.ID]; ok && ev.Time.After(s) {
			e.lastRuns[ev.ID] = ev.Time.Sub(s)
		} else {
			delete(e.lastRuns, ev.ID)
		}
	}
}

// track updates one level-triggered problem, identified by key, with
// its current state (issue nil = not happening). It returns what to
// send: the issue when the episode starts, a resolution when it ends,
// nil otherwise. current, if given, is the container's latest state for
// the resolution.
func (e *Engine) track(key string, issue *detector.Issue, current *detector.ContainerSnapshot) *detector.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.trackLocked(key, issue, current)
}

func (e *Engine) trackLocked(key string, issue *detector.Issue, current *detector.ContainerSnapshot) *detector.Issue {
	a, active := e.active[key]
	switch {
	case issue != nil && !active:
		issue.Key = key
		e.active[key] = &activeAlert{issue: *issue, since: e.now(), containerID: issue.Container.ID}
		return issue
	case issue == nil && active:
		delete(e.active, key)
		r := e.resolution(a, "resolved")
		if current != nil {
			r.Container = *current
		}
		return r
	}
	return nil
}

// trackSet is track for a detector that reports all of its current
// problems at once: anything that was open and isn't reported anymore
// is resolved.
func (e *Engine) trackSet(name string, issues []*detector.Issue, id func(*detector.Issue) string) []*detector.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()

	prefix := name + "/"
	current := make(map[string]bool, len(issues))
	var out []*detector.Issue
	for _, issue := range issues {
		key := prefix + id(issue)
		current[key] = true
		if o := e.trackLocked(key, issue, nil); o != nil {
			out = append(out, o)
		}
	}
	for key := range e.active {
		if strings.HasPrefix(key, prefix) && !current[key] {
			out = append(out, e.trackLocked(key, nil, nil))
		}
	}
	return out
}

// resolveContainer closes every open episode for a container that was
// removed.
func (e *Engine) resolveContainer(id string) []*detector.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []*detector.Issue
	for key, a := range e.active {
		if a.containerID == id {
			delete(e.active, key)
			out = append(out, e.resolution(a, "container removed"))
		}
	}
	return out
}

func (e *Engine) resolution(a *activeAlert, reason string) *detector.Issue {
	now := e.now()
	r := a.issue
	r.Resolved = true
	r.Logs = nil
	r.Analysis = ""
	r.DetectedAt = now
	r.Message = fmt.Sprintf("%s after %s (was: %s)", reason, formatDuration(now.Sub(a.since)), a.issue.Message)
	return &r
}

// coolingDown applies the cooldown to one-off alerts and records the
// ones that pass.
func (e *Engine) coolingDown(issue *detector.Issue) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	for key, t := range e.lastAlert {
		if now.Sub(t) >= e.opts.AlertCooldown {
			delete(e.lastAlert, key)
		}
	}
	key := issue.Detector + "/" + issue.Container.Name
	if _, ok := e.lastAlert[key]; ok {
		slog.Debug("alert suppressed by cooldown", "detector", issue.Detector, "container", issue.Container.Name)
		return true
	}
	if e.opts.AlertCooldown > 0 {
		e.lastAlert[key] = now
	}
	return false
}

// report fetches logs once for all new alerts of a container, scrubs
// everything, and queues it for dispatch. Resolutions don't get logs.
func (e *Engine) report(ctx context.Context, containerID string, tty bool, issues []*detector.Issue) {
	if len(issues) == 0 {
		return
	}

	var logs []string
	if containerID != "" && hasFiring(issues) {
		var err error
		logs, err = e.docker.ContainerLogs(ctx, containerID, logsTail, tty)
		if err != nil {
			logContainerErr("fetch logs failed", issues[0].Container.Name, err)
		}
		for i, line := range logs {
			logs[i] = detector.Truncate(line, maxLogLine)
		}
		logs = e.opts.Redactor.Strings(logs)
	}

	for _, issue := range issues {
		if !issue.Resolved {
			issue.Logs = logs
		}
		issue.Host = e.opts.Hostname
		issue.Message = e.opts.Redactor.String(issue.Message)
		e.queue <- *issue
	}
}

func hasFiring(issues []*detector.Issue) bool {
	for _, issue := range issues {
		if !issue.Resolved {
			return true
		}
	}
	return false
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
		ID:            inspect.ID,
		Name:          name,
		Status:        inspect.State.Status,
		RestartCount:  inspect.RestartCount,
		ExitCode:      inspect.State.ExitCode,
		OOMKilled:     inspect.State.OOMKilled,
		StartedAt:     parseTime(inspect.State.StartedAt),
		FinishedAt:    parseTime(inspect.State.FinishedAt),
		Image:         inspect.Config.Image,
		ImageID:       inspect.Image,
		Created:       parseTime(inspect.Created),
		RestartPolicy: restartPolicy(inspect),
		Labels:        detector.RelevantLabels(inspect.Config.Labels),
	}
	if inspect.HostConfig.Memory > 0 {
		snap.MemoryMax = uint64(inspect.HostConfig.Memory)
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

func restartPolicy(inspect *dockerclient.ContainerInspect) string {
	rp := inspect.HostConfig.RestartPolicy
	switch {
	case rp.Name == "":
		return ""
	case rp.MaximumRetryCount > 0:
		return fmt.Sprintf("%s:%d", rp.Name, rp.MaximumRetryCount)
	default:
		return rp.Name
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() <= 1 {
		return time.Time{}
	}
	return t
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

// formatDuration renders a duration the way a person would say it:
// 45s, 12m, 3h5m.
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Round(time.Second).Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	default:
		d = d.Round(time.Minute)
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
}
