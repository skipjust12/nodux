package engine

import (
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	stateVersion = 1

	// maxReplay bounds how far back the event stream is replayed after
	// a restart. The daemon only buffers a few hundred events anyway, and
	// a crash from days ago isn't news.
	maxReplay = time.Hour
)

// savedState is what survives a restart. Map keys are sorted by
// encoding/json and episodes by key, so an unchanged state encodes to
// the same bytes and isn't rewritten.
type savedState struct {
	Version   int                        `json:"version"`
	Events    savedEvents                `json:"events"`
	Episodes  []savedEpisode             `json:"episodes"`
	Cooldowns map[string]time.Time       `json:"cooldowns,omitempty"`
	Images    map[string]*imageInfo      `json:"images,omitempty"`
	Detectors map[string]json.RawMessage `json:"detectors,omitempty"`
	Incidents json.RawMessage            `json:"incidents,omitempty"`
}

type savedEvents struct {
	Since   time.Time `json:"since"`
	Handled []string  `json:"handled,omitempty"`
}

type savedEpisode struct {
	Key         string         `json:"key"`
	Since       time.Time      `json:"since"`
	ContainerID string         `json:"container_id,omitempty"`
	Issue       detector.Issue `json:"issue"`
}

// saveState writes the state file. It runs on the poll loop (whose
// detectors are therefore idle) and pauses the event loop for a moment,
// so event detector state, open episodes and the stream position all
// describe the same point in time.
func (e *Engine) saveState() {
	if e.opts.State == nil {
		return
	}
	e.eventMu.Lock()
	defer e.eventMu.Unlock()

	st := savedState{Version: stateVersion, Events: savedEvents{Since: e.evSince}}
	if e.evSince.Equal(e.evLast) {
		for k := range e.evHandled {
			st.Events.Handled = append(st.Events.Handled, k)
		}
		sort.Strings(st.Events.Handled)
	}

	e.mu.Lock()
	for key, a := range e.active {
		issue := a.issue
		issue.Logs = nil
		st.Episodes = append(st.Episodes, savedEpisode{Key: key, Since: a.since, ContainerID: a.containerID, Issue: issue})
	}
	if len(e.lastAlert) > 0 {
		st.Cooldowns = make(map[string]time.Time, len(e.lastAlert))
		for k, v := range e.lastAlert {
			st.Cooldowns[k] = v
		}
	}
	if len(e.images) > 0 {
		st.Images = make(map[string]*imageInfo, len(e.images))
		for k, v := range e.images {
			img := *v
			st.Images[k] = &img
		}
	}
	e.mu.Unlock()
	sort.Slice(st.Episodes, func(i, j int) bool { return st.Episodes[i].Key < st.Episodes[j].Key })

	st.Detectors = make(map[string]json.RawMessage, len(e.stateful))
	for _, d := range e.stateful {
		raw, err := d.SaveState()
		if err != nil {
			slog.Warn("saving detector state failed", "detector", d.Name(), "error", err)
			continue
		}
		st.Detectors[d.Name()] = raw
	}
	if raw, err := e.grouper.SaveState(); err == nil {
		st.Incidents = raw
	}

	if err := e.opts.State.Save(st); err != nil {
		if !e.saveFailing {
			slog.Error("saving state failed", "path", e.opts.State.Path(), "error", err)
		}
		e.saveFailing = true
		return
	}
	if e.saveFailing {
		slog.Info("saving state works again", "path", e.opts.State.Path())
	}
	e.saveFailing = false
}

// restore loads the state file before the loops start: open episodes
// (so what's still broken isn't alerted on again, and what got fixed
// meanwhile is resolved), detector state, cooldowns, and where to
// resume the event stream.
func (e *Engine) restore() {
	now := e.now()
	e.evSince = now
	if e.opts.State == nil {
		return
	}
	var st savedState
	ok, err := e.opts.State.Load(&st)
	if err != nil {
		slog.Warn("ignoring unreadable state file, starting fresh", "path", e.opts.State.Path(), "error", err)
		return
	}
	if !ok {
		return
	}
	if st.Version != stateVersion {
		slog.Warn("ignoring state file from another version, starting fresh", "path", e.opts.State.Path(), "version", st.Version)
		return
	}

	known := e.knownDetectors()
	e.mu.Lock()
	for _, ep := range st.Episodes {
		name, _, _ := strings.Cut(ep.Key, "/")
		if !known[name] {
			continue // detector turned off since: nobody would resolve it
		}
		if _, excluded := e.excludeContainers[ep.Issue.Container.Name]; excluded && ep.Issue.Container.Name != "" {
			continue // excluded since: it's never checked again
		}
		ep.Issue.Key = ep.Key
		e.active[ep.Key] = &activeAlert{issue: ep.Issue, since: ep.Since, containerID: ep.ContainerID}
		if ep.ContainerID != "" {
			// The first poll resolves episodes of containers removed while
			// nodux was down, as if it had seen them disappear.
			e.lastSeen[ep.ContainerID] = struct{}{}
		}
	}
	for k, v := range st.Cooldowns {
		e.lastAlert[k] = v
	}
	for k, v := range st.Images {
		if v != nil {
			e.images[k] = v
		}
	}
	open := len(e.active)
	e.mu.Unlock()

	for _, d := range e.stateful {
		if raw, ok := st.Detectors[d.Name()]; ok {
			if err := d.LoadState(raw); err != nil {
				slog.Warn("ignoring saved detector state", "detector", d.Name(), "error", err)
			}
		}
	}
	if len(st.Incidents) > 0 {
		if err := e.grouper.LoadState(st.Incidents); err != nil {
			slog.Warn("ignoring saved incident state", "error", err)
		}
	}

	since := st.Events.Since
	switch {
	case since.IsZero() || since.After(now):
	case now.Sub(since) > maxReplay:
		e.evSince = now.Add(-maxReplay)
	default:
		e.evSince, e.evLast = since, since
		for _, k := range st.Events.Handled {
			e.evHandled[k] = true
		}
	}
	slog.Info("restored state", "path", e.opts.State.Path(), "open_alerts", open, "events_since", e.evSince.UTC().Format(time.RFC3339))
}

// knownDetectors are the detectors that can open episodes in this
// configuration.
func (e *Engine) knownDetectors() map[string]bool {
	known := make(map[string]bool)
	for _, d := range e.opts.Detectors {
		known[d.Name()] = true
	}
	for name := range e.levelEvents {
		known[name] = true
	}
	for _, d := range e.opts.HostDetectors {
		known[d.Name()] = true
	}
	if e.opts.Expected != nil {
		known[e.opts.Expected.Name()] = true
	}
	if e.opts.DockerDownAfter > 0 {
		known[dockerDetector] = true
	}
	return known
}
