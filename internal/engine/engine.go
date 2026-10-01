// Package engine wires the docker client, detectors, actions, and the
// LLM layer together. It runs up to three loops side by side: a poll
// loop that checks the host and feeds container snapshots to Detectors,
// an event loop that feeds the daemon's event stream to EventDetectors,
// and a probe loop for checks that go over the network. Alerts go out
// through a dispatcher goroutine, so a slow LLM call or action never
// holds up detection.
package engine

import (
	"context"
	"errors"
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
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
	"github.com/skipjust12/nodux/internal/silence"
)

const (
	logsTail       = 20
	maxLogLine     = 1000 // bytes; a single huge line shouldn't bloat every payload
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second

	queueSize       = 256
	classifyBatch   = 16
	classifyWorkers = 4

	dockerDetector = "docker"
)

type Options struct {
	Detectors      []detector.Detector
	EventDetectors []detector.EventDetector
	HostDetectors  []detector.HostDetector
	Expected       *detector.ExpectedDetector
	Actions        []action.Action
	// Classifier annotates container alerts with a probable cause.
	// nil disables it.
	Classifier llm.Classifier
	// Redactor scrubs messages and logs before they leave the host (and
	// before they reach the classifier). nil disables it.
	Redactor *redact.Redactor
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
	// CollectThrottling does the same for containers with a CPU limit,
	// for the cpu_throttle detector. A container that needs both gets
	// one call.
	CollectThrottling bool
	// HostOOM watches the kernel's OOM kill counter; it's fed container
	// OOM events so it can tell host OOMs apart. nil disables it.
	HostOOM *detector.HostOOMDetector
	// Probes are host detectors that go over the network (HTTP/TCP/TLS
	// checks). They run on their own loop every ProbeInterval, in order,
	// so a slow target never holds up the poll loop.
	Probes        []detector.HostDetector
	ProbeInterval time.Duration
	// Silences mutes alerts on their way to receivers. nil disables
	// silences altogether.
	Silences *silence.Store
	// DeployGrace is how long the deploy window for a container (and its
	// compose project) stays open after its last create, stop or destroy
	// event. Zero disables deploy windows.
	DeployGrace time.Duration
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

	// Only touched by the poll loop.
	lastSeen map[string]struct{}

	// mu guards everything below up to counts; the poll, event and
	// probe loops all report issues.
	mu         sync.Mutex
	lastAlert  map[string]time.Time // "detector/container name" -> when
	active     map[string]*activeAlert
	containers map[string]containerRef // by name, as of the last poll
	lastPoll   time.Time
	counts     map[AlertKey]uint64
	now        func() time.Time

	healthy atomic.Bool
	queue   chan detector.Issue
}

// activeAlert is an open level-triggered episode.
type activeAlert struct {
	issue       detector.Issue
	since       time.Time
	containerID string // for resolving when the container goes away
	// notified is false while the episode's alert is held back by a
	// silence; it goes out once the silence ends, if the episode is
	// still open. A resolution is only sent for a notified episode.
	notified bool
}

type containerRef struct {
	id      string
	project string
	tty     bool
}

// AlertKey identifies an alert counter.
type AlertKey struct {
	Detector string
	Severity string
	State    string // firing or resolved
	Silenced bool
}

// Episode is an open level-triggered problem, for status reporting.
type Episode struct {
	Detector  string    `json:"detector"`
	Severity  string    `json:"severity"`
	Container string    `json:"container,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Message   string    `json:"message"`
	Since     time.Time `json:"since"`
	// Silenced: the alert hasn't been sent, because of a silence.
	Silenced bool `json:"silenced,omitempty"`
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
	return &Engine{
		docker:            docker,
		opts:              opts,
		minBackoff:        initialBackoff,
		excludeContainers: exclude,
		levelEvents:       levelEvents,
		lastSeen:          make(map[string]struct{}),
		lastAlert:         make(map[string]time.Time),
		active:            make(map[string]*activeAlert),
		containers:        make(map[string]containerRef),
		counts:            make(map[AlertKey]uint64),
		now:               time.Now,
		queue:             make(chan detector.Issue, queueSize),
	}
}

// Healthy reports whether the last poll of the Docker daemon worked.
// The heartbeat only pings while it does.
func (e *Engine) Healthy() bool { return e.healthy.Load() }

// LastPoll is when the Docker daemon was last polled successfully.
func (e *Engine) LastPoll() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastPoll
}

// Episodes returns the open level-triggered problems, oldest first.
func (e *Engine) Episodes() []Episode {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Episode, 0, len(e.active))
	for _, a := range e.active {
		out = append(out, Episode{
			Detector:  a.issue.Detector,
			Severity:  a.issue.Severity,
			Container: a.issue.Container.Name,
			Resource:  a.issue.Resource,
			Message:   a.issue.Message,
			Since:     a.since,
			Silenced:  !a.notified,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.Before(out[j].Since)
		}
		return out[i].Detector+out[i].Container+out[i].Resource < out[j].Detector+out[j].Container+out[j].Resource
	})
	return out
}

// AlertCounts returns how many alerts and resolutions have been
// dispatched since startup.
func (e *Engine) AlertCounts() map[AlertKey]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[AlertKey]uint64, len(e.counts))
	for k, v := range e.counts {
		out[k] = v
	}
	return out
}

// Run drives both loops until ctx is cancelled, then delivers whatever
// alerts are still queued. Docker socket errors don't crash the daemon:
// they're logged, and each loop retries with exponential backoff.
func (e *Engine) Run(ctx context.Context) {
	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		e.dispatch(ctx)
	}()

	var wg sync.WaitGroup
	if e.needEvents() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runEvents(ctx)
		}()
	}
	if len(e.opts.Probes) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runProbes(ctx)
		}()
	}
	e.runPoll(ctx)
	wg.Wait()

	close(e.queue)
	<-dispatched
}

func (e *Engine) needEvents() bool {
	return len(e.opts.EventDetectors) > 0 || e.opts.HostOOM != nil || e.deployWindows()
}

func (e *Engine) deployWindows() bool {
	return e.opts.Silences != nil && e.opts.DeployGrace > 0
}

func (e *Engine) runPoll(ctx context.Context) {
	backoff := e.minBackoff
	var downSince time.Time

	for {
		if ctx.Err() != nil {
			return
		}
		e.checkHost(ctx)
		e.flushDeferred(ctx)

		if err := e.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			e.healthy.Store(false)
			if downSince.IsZero() {
				downSince = e.now()
			}
			e.dockerDown(ctx, downSince, err)
			slog.Error("poll failed, will retry", "error", err, "retry_in", backoff.String())
			if !sleep(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		e.healthy.Store(true)
		if !downSince.IsZero() {
			downSince = time.Time{}
			e.dockerUp(ctx)
		}
		backoff = e.minBackoff
		if !sleep(ctx, e.opts.PollInterval) {
			return
		}
	}
}

// runEvents keeps the event stream open. After a disconnect it resumes
// from the last event it processed, so events that happened while the
// stream was down are replayed instead of lost.
func (e *Engine) runEvents(ctx context.Context) {
	since := e.now()
	// The daemon replays everything from `since` inclusive, and distinct
	// events can share a timestamp, so remember which ones at the last
	// timestamp were already handled.
	var last time.Time
	handledAtLast := make(map[string]bool)
	backoff := e.minBackoff

	for {
		connectedAt := time.Now()
		err := e.docker.Events(ctx, since, detector.EventActions, func(ev dockerclient.Event) {
			t := time.Unix(0, ev.TimeNano)
			key := ev.Action + "/" + ev.Actor.ID
			switch {
			case t.Before(last):
				return
			case t.Equal(last):
				if handledAtLast[key] {
					return
				}
			default:
				last = t
				clear(handledAtLast)
			}
			handledAtLast[key] = true
			since = t
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
	if e.opts.HostOOM != nil {
		if issue := e.opts.HostOOM.Check(); issue != nil {
			issue.Silenced = e.isSilenced(issue)
			e.report(ctx, "", false, []*detector.Issue{issue})
		}
	}
}

// runProbes runs the probe detectors right away and then every
// ProbeInterval. A probe tied to a container gets that container's state
// and logs, like any container alert.
func (e *Engine) runProbes(ctx context.Context) {
	for {
		for _, d := range e.opts.Probes {
			if ctx.Err() != nil {
				return
			}
			out := e.trackSet(d.Name(), d.Check(), func(i *detector.Issue) string { return i.Resource })
			for _, issue := range out {
				var id string
				tty := false
				if issue.Container.Name != "" && !issue.Resolved {
					e.mu.Lock()
					ref, ok := e.containers[issue.Container.Name]
					e.mu.Unlock()
					if ok {
						id, tty = ref.id, ref.tty
						if inspect, err := e.docker.InspectContainer(ctx, id); err == nil {
							issue.Container = toSnapshot(issue.Container.Name, inspect)
						} else {
							issue.Container.ID = id
						}
					}
				}
				e.report(ctx, id, tty, []*detector.Issue{issue})
			}
		}
		interval := e.opts.ProbeInterval
		if interval <= 0 {
			interval = e.opts.PollInterval
		}
		if !sleep(ctx, interval) {
			return
		}
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

func (e *Engine) pollOnce(ctx context.Context) error {
	if err := e.docker.Ping(ctx); err != nil {
		return err
	}

	summaries, err := e.docker.ListContainers(ctx)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(summaries))
	statuses := make(map[string]string, len(summaries))
	refs := make(map[string]containerRef, len(summaries))
	for _, summary := range summaries {
		seen[summary.ID] = struct{}{}

		name := containerName(summary)
		statuses[name] = summary.State
		refs[name] = containerRef{id: summary.ID, project: summary.Labels[dockerclient.ProjectLabel]}
		if _, excluded := e.excludeContainers[name]; excluded || len(e.opts.Detectors) == 0 {
			continue
		}

		// An event that opens an episode after this point is newer than
		// what we're about to look at; it mustn't be closed on stale data.
		observedAt := e.now()
		inspect, err := e.docker.InspectContainer(ctx, summary.ID)
		if err != nil {
			logContainerErr("inspect failed, skipping container this round", name, err)
			continue
		}
		ref := refs[name]
		ref.tty = inspect.Config.Tty
		refs[name] = ref

		snapshot := toSnapshot(name, inspect)
		e.collectStats(ctx, inspect, &snapshot)

		var out []*detector.Issue
		for _, d := range e.opts.Detectors {
			issue := d.Check(snapshot)
			if o := e.trackAt(d.Name()+"/"+summary.ID, issue, &snapshot, observedAt); o != nil {
				out = append(out, o)
			}
		}
		e.report(ctx, summary.ID, inspect.Config.Tty, out)
	}

	e.mu.Lock()
	for name, ref := range refs {
		if old, ok := e.containers[name]; ok && old.id == ref.id && !ref.tty {
			ref.tty = old.tty // excluded containers aren't inspected
		}
		refs[name] = ref
	}
	e.containers = refs
	e.lastPoll = e.now()
	e.mu.Unlock()

	if e.opts.Expected != nil {
		out := e.trackSet(e.opts.Expected.Name(), e.opts.Expected.Check(statuses), func(i *detector.Issue) string { return i.Container.Name })
		for _, issue := range out {
			// An existing but stopped container has logs worth seeing.
			id := refs[issue.Container.Name].id
			if !issue.Resolved {
				issue.Container.ID = id
			}
			e.report(ctx, id, false, []*detector.Issue{issue})
		}
	}

	e.forgetGone(ctx, seen)
	return nil
}

// collectStats fills in memory and CPU throttling numbers for a running
// container that has the corresponding limit, if a detector wants them.
func (e *Engine) collectStats(ctx context.Context, inspect *dockerclient.ContainerInspect, snap *detector.ContainerSnapshot) {
	if !inspect.State.Running {
		return
	}
	needMem := e.opts.CollectStats && inspect.HostConfig.Memory > 0
	cpuLimit := inspect.CPULimit()
	needCPU := e.opts.CollectThrottling && cpuLimit > 0
	if !needMem && !needCPU {
		return
	}
	stats, err := e.docker.ContainerStats(ctx, inspect.ID)
	if err != nil {
		logContainerErr("fetch stats failed", snap.Name, err)
		return
	}
	if needMem {
		snap.MemoryUsed = stats.MemoryUsed()
		snap.MemoryLimit = stats.MemoryStats.Limit
	}
	if needCPU {
		t := stats.CPUStats.ThrottlingData
		snap.CPULimit = cpuLimit
		snap.CPUPeriods = t.Periods
		snap.CPUThrottledPeriods = t.ThrottledPeriods
	}
}

// forgetGone drops detector state for containers that were present on
// the previous poll but have since been removed, and closes their open
// episodes.
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
		e.report(ctx, "", false, e.resolveContainer(id))
	}
	e.lastSeen = seen
}

func (e *Engine) handleEvent(ctx context.Context, ev dockerclient.Event, t time.Time) {
	name := strings.TrimPrefix(ev.Actor.Attributes["name"], "/")
	cev := detector.ContainerEvent{
		ID:       ev.Actor.ID,
		Name:     name,
		Action:   ev.Action,
		Project:  ev.Actor.Attributes[dockerclient.ProjectLabel],
		ExitCode: eventExitCode(ev.Actor.Attributes),
		Signal:   detector.ParseSignal(ev.Actor.Attributes["signal"]),
		Time:     t,
	}
	// Docker: "health_status: unhealthy"; Podman: "health_status" with
	// the status in an attribute.
	if action, status, ok := strings.Cut(cev.Action, ":"); ok && action == "health_status" {
		cev.Action, cev.HealthStatus = action, strings.TrimSpace(status)
	} else if cev.Action == "health_status" {
		cev.HealthStatus = ev.Actor.Attributes["health_status"]
	}

	// Every container OOM, excluded containers' too, so it isn't taken
	// for a host OOM.
	if cev.Action == "oom" && e.opts.HostOOM != nil {
		e.opts.HostOOM.ContainerOOM()
	}
	if _, excluded := e.excludeContainers[name]; excluded {
		return
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
	if e.deployWindows() && isDeployEvent(cev) {
		e.opts.Silences.Deploy(name, cev.Project, t.Add(e.opts.DeployGrace))
	}

	type found struct {
		d     detector.EventDetector
		issue *detector.Issue
	}
	var hits []found
	for _, d := range e.opts.EventDetectors {
		issue := d.HandleEvent(cev)
		if issue == nil {
			continue
		}
		if !e.levelEvents[d.Name()] && e.coolingDown(issue) {
			continue
		}
		hits = append(hits, found{d, issue})
	}

	if len(hits) > 0 {
		// Fill in the rest of the container state. The container may
		// already be gone (docker run --rm); then the event data is all
		// we have.
		tty := false
		inspect, err := e.docker.InspectContainer(ctx, cev.ID)
		var snap detector.ContainerSnapshot
		if err == nil {
			tty = inspect.Config.Tty
			snap = toSnapshot(name, inspect)
		}
		var issues []*detector.Issue
		for _, h := range hits {
			issue := h.issue
			if err == nil {
				issue.Container = mergeSnapshot(issue.Container, snap)
			}
			if c, ok := h.d.(detector.Confirmer); ok {
				if issue = c.Confirm(issue.Container); issue == nil {
					continue
				}
			}
			if e.levelEvents[h.d.Name()] {
				issue = e.track(h.d.Name()+"/"+cev.ID, issue, nil)
			} else {
				issue.Silenced = e.isSilenced(issue)
			}
			if issue != nil {
				issues = append(issues, issue)
			}
		}
		e.report(ctx, cev.ID, tty, issues)
	}

	if cev.Action == "destroy" {
		e.report(ctx, "", false, e.resolveContainer(cev.ID))
	}
}

// isDeployEvent reports whether an event means someone is working on
// the container: creating it (compose up, docker run), stopping it, or
// removing it. Restarts by a restart policy are none of these.
func isDeployEvent(ev detector.ContainerEvent) bool {
	switch ev.Action {
	case "create", "destroy":
		return true
	case "kill":
		return detector.IsStopRequest(ev)
	}
	return false
}

// track updates one level-triggered problem, identified by key, with
// its current state (issue nil = not happening). It returns what to
// send: the issue when the episode starts, a resolution when it ends,
// nil otherwise. current, if given, is the container's latest state for
// the resolution.
func (e *Engine) track(key string, issue *detector.Issue, current *detector.ContainerSnapshot) *detector.Issue {
	return e.trackAt(key, issue, current, time.Time{})
}

// trackAt is track for an observation made at observedAt: an episode
// opened after that (by an event) isn't closed by it.
func (e *Engine) trackAt(key string, issue *detector.Issue, current *detector.ContainerSnapshot, observedAt time.Time) *detector.Issue {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a, ok := e.active[key]; ok && issue == nil && !observedAt.IsZero() && a.since.After(observedAt) {
		return nil
	}
	return e.trackLocked(key, issue, current)
}

func (e *Engine) trackLocked(key string, issue *detector.Issue, current *detector.ContainerSnapshot) *detector.Issue {
	a, active := e.active[key]
	switch {
	case issue != nil && !active:
		issue.Silenced = e.silencedLocked(issue, false)
		stored := *issue
		stored.Silenced = false
		e.active[key] = &activeAlert{issue: stored, since: e.now(), containerID: issue.Container.ID, notified: !issue.Silenced}
		return issue
	case issue != nil && active && detector.SeverityRank(issue.Severity) > detector.SeverityRank(a.issue.Severity):
		// Escalation (a certificate going from 14 days left to 2): a new
		// alert within the same episode.
		issue.Silenced = e.silencedLocked(issue, false)
		a.issue = *issue
		a.issue.Silenced = false
		if !issue.Silenced {
			a.notified = true
		}
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
	// Nobody heard about the problem, so nobody needs to hear it's over.
	r.Silenced = !a.notified
	return &r
}

// isSilenced reports whether a one-off alert matches a silence. Deploy
// windows don't apply to one-off alerts.
func (e *Engine) isSilenced(issue *detector.Issue) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.silencedLocked(issue, true)
}

// silencedLocked reports whether an alert matches a silence or, unless
// it's a one-off alert, a deploy window.
func (e *Engine) silencedLocked(issue *detector.Issue, oneOff bool) bool {
	if e.opts.Silences == nil {
		return false
	}
	c := issue.Container
	project := c.Project
	if project == "" && c.Name != "" {
		project = e.containers[c.Name].project
	}
	reason, ok := e.opts.Silences.Silenced(silence.Subject{
		Detector:  issue.Detector,
		Container: c.Name,
		Project:   project,
		Resource:  issue.Resource,
		OneOff:    oneOff,
	})
	if ok {
		slog.Debug("alert silenced", "detector", issue.Detector, "container", c.Name, "resource", issue.Resource, "by", reason)
	}
	return ok
}

// flushDeferred sends the alerts of episodes that opened during a
// silence and are still open now that it's over.
func (e *Engine) flushDeferred(ctx context.Context) {
	if e.opts.Silences == nil {
		return
	}
	var out []detector.Issue
	e.mu.Lock()
	now := e.now()
	for _, a := range e.active {
		if a.notified || e.silencedLocked(&a.issue, false) {
			continue
		}
		a.notified = true
		issue := a.issue
		if c := &issue.Container; c.ID == "" && c.Name != "" {
			// A probe tied to a container, or an expected container.
			ref := e.containers[c.Name]
			c.ID, c.Tty = ref.id, ref.tty
		}
		issue.DetectedAt = now
		issue.Message += fmt.Sprintf(" (open for %s, held back by a silence until now)", formatDuration(now.Sub(a.since)))
		out = append(out, issue)
	}
	e.mu.Unlock()

	for i := range out {
		issue := &out[i]
		if c := issue.Container; c.ID != "" && c.Status == "" {
			// Only a name was known when the episode opened.
			if inspect, err := e.docker.InspectContainer(ctx, c.ID); err == nil {
				issue.Container = toSnapshot(c.Name, inspect)
			}
		}
		e.report(ctx, issue.Container.ID, issue.Container.Tty, []*detector.Issue{issue})
	}
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
	if containerID != "" && hasAudible(issues) {
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
		if !issue.Resolved && !issue.Silenced {
			issue.Logs = logs
		}
		issue.Host = e.opts.Hostname
		issue.Message = e.opts.Redactor.String(issue.Message)
		e.queue <- *issue
	}
}

// hasAudible reports whether any issue is a firing alert that will be
// sent (silenced ones only go to the local log, without logs).
func hasAudible(issues []*detector.Issue) bool {
	for _, issue := range issues {
		if !issue.Resolved && !issue.Silenced {
			return true
		}
	}
	return false
}

// dispatch sends queued alerts to every action until the queue is
// closed. Alerts that arrive together are classified concurrently, then
// sent in order. Once ctx is cancelled (shutting down), classification
// is skipped so pending alerts go out right away.
func (e *Engine) dispatch(ctx context.Context) {
	for first := range e.queue {
		batch := []detector.Issue{first}
	drain:
		for len(batch) < classifyBatch {
			select {
			case issue, ok := <-e.queue:
				if !ok {
					break drain
				}
				batch = append(batch, issue)
			default:
				break drain
			}
		}

		e.classify(ctx, batch)
		for _, issue := range batch {
			e.count(issue)
			for _, a := range e.opts.Actions {
				if err := a.Run(context.Background(), issue); err != nil {
					slog.Error("action failed", "action", a.Name(), "detector", issue.Detector, "container", issue.Container.Name, "error", err)
				}
			}
		}
	}
}

func (e *Engine) count(issue detector.Issue) {
	state := "firing"
	if issue.Resolved {
		state = "resolved"
	}
	e.mu.Lock()
	e.counts[AlertKey{Detector: issue.Detector, Severity: issue.Severity, State: state, Silenced: issue.Silenced}]++
	e.mu.Unlock()
}

func (e *Engine) classify(ctx context.Context, batch []detector.Issue) {
	if e.opts.Classifier == nil || ctx.Err() != nil {
		return
	}
	sem := make(chan struct{}, classifyWorkers)
	var wg sync.WaitGroup
	for i := range batch {
		issue := &batch[i]
		// Only container alerts come with logs to reason about, and
		// silenced ones aren't worth the budget.
		if issue.Resolved || issue.Silenced || issue.Container.Name == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			analysis, err := e.opts.Classifier.Classify(ctx, *issue)
			switch {
			case errors.Is(err, llm.ErrBudgetExhausted):
				slog.Debug("llm budget exhausted, sending alert without analysis", "detector", issue.Detector)
			case err != nil:
				slog.Warn("llm classification failed", "detector", issue.Detector, "container", issue.Container.Name, "error", err)
			default:
				issue.Analysis = analysis
			}
		}()
	}
	wg.Wait()
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
		ID:           inspect.ID,
		Name:         name,
		Status:       inspect.State.Status,
		RestartCount: inspect.RestartCount,
		ExitCode:     inspect.State.ExitCode,
		OOMKilled:    inspect.State.OOMKilled,
		StartedAt:    parseTime(inspect.State.StartedAt),
		FinishedAt:   parseTime(inspect.State.FinishedAt),
		Project:      inspect.Config.Labels[dockerclient.ProjectLabel],
		Tty:          inspect.Config.Tty,
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
