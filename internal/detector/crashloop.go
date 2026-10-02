package detector

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// CrashLoopDetector fires when a container has been restarted after a
// crash threshold times within the sliding window.
//
// Restarts come from the event stream, with exact timestamps: a "start"
// that follows a "die" nobody asked for (no stopping "kill" in between)
// is a restart after a crash, whether a restart policy or a person did
// it. Manual restarts (docker restart, compose up) don't count.
//
// It's both an EventDetector, so the alert goes out the moment the
// threshold is crossed, and a poll Detector, which keeps the episode
// open until the container has run for a full window without a restart,
// and then lets the engine send the resolution. A container that gave
// up (restart policy exhausted, status exited) stays in the episode.
//
// nodux.crashloop.threshold and nodux.crashloop.window override the
// defaults per container.
type CrashLoopDetector struct {
	threshold int
	window    time.Duration
	now       func() time.Time // overridable for tests

	// Fed from the event loop and read from the poll loop.
	mu      sync.Mutex
	stops   stopTracker
	crashed map[string]int // exit code of a die without a stop request, until the next start
	state   map[string]*crashLoopState
}

type crashLoopState struct {
	Restarts  []time.Time   `json:"restarts,omitempty"`
	Firing    bool          `json:"firing,omitempty"`
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"window"`
}

func NewCrashLoopDetector(threshold int, window time.Duration) *CrashLoopDetector {
	return &CrashLoopDetector{
		threshold: threshold,
		window:    window,
		now:       time.Now,
		stops:     make(stopTracker),
		crashed:   make(map[string]int),
		state:     make(map[string]*crashLoopState),
	}
}

func (d *CrashLoopDetector) Name() string { return "crashloop" }

func (d *CrashLoopDetector) HandleEvent(ev ContainerEvent) *Issue {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stops.observe(ev)
	switch ev.Action {
	case "die":
		if d.stops[ev.ID] {
			delete(d.crashed, ev.ID)
		} else {
			d.crashed[ev.ID] = ev.ExitCode
		}
	case "destroy":
		d.forget(ev.ID)
	case "start":
		exitCode, wasCrash := d.crashed[ev.ID]
		delete(d.crashed, ev.ID)
		if !wasCrash {
			return nil
		}
		st := d.state[ev.ID]
		if st == nil {
			st = d.newState(ev.Labels)
			d.state[ev.ID] = st
		}
		st.Restarts = append(st.Restarts, ev.Time)
		st.prune(ev.Time.Add(-st.Window))
		if st.Firing || len(st.Restarts) < st.Threshold {
			return nil
		}
		st.Firing = true
		return d.issue(ContainerSnapshot{ID: ev.ID, Name: ev.Name, ExitCode: exitCode, Labels: ev.Labels}, st, len(st.Restarts), ev.Time)
	}
	return nil
}

func (d *CrashLoopDetector) newState(labels map[string]string) *crashLoopState {
	st := &crashLoopState{Threshold: d.threshold, Window: d.window}
	if n, ok := labelPositiveInt(labels, "nodux.crashloop.threshold"); ok {
		st.Threshold = n
	}
	if w, ok := labelDuration(labels, "nodux.crashloop.window"); ok && w > 0 {
		st.Window = w
	}
	return st
}

func (d *CrashLoopDetector) Check(s ContainerSnapshot) *Issue {
	d.mu.Lock()
	defer d.mu.Unlock()

	st := d.state[s.ID]
	if st == nil {
		return nil
	}
	now := d.now()
	st.prune(now.Add(-st.Window))

	if !st.Firing {
		if len(st.Restarts) < st.Threshold {
			if len(st.Restarts) == 0 {
				delete(d.state, s.ID)
			}
			return nil
		}
		st.Firing = true
	}
	if len(st.Restarts) == 0 && s.Status == "running" {
		delete(d.state, s.ID)
		return nil
	}
	return d.issue(s, st, len(st.Restarts), now)
}

func (d *CrashLoopDetector) issue(s ContainerSnapshot, st *crashLoopState, restarts int, at time.Time) *Issue {
	msg := fmt.Sprintf("container restarted %d times in the last %s after crashing", restarts, st.Window)
	if restarts == 0 {
		msg = fmt.Sprintf("container stopped after crash-looping (status: %s)", s.Status)
	}
	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityCritical,
		Message:    msg,
		Container:  s,
		DetectedAt: at,
	}
}

func (st *crashLoopState) prune(cutoff time.Time) {
	kept := st.Restarts[:0]
	for _, t := range st.Restarts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.Restarts = kept
}

func (d *CrashLoopDetector) Forget(containerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forget(containerID)
}

func (d *CrashLoopDetector) forget(id string) {
	delete(d.state, id)
	delete(d.crashed, id)
	delete(d.stops, id)
}

type crashLoopSaved struct {
	Stops   map[string]bool            `json:"stops,omitempty"`
	Crashed map[string]int             `json:"crashed,omitempty"`
	State   map[string]*crashLoopState `json:"state,omitempty"`
}

func (d *CrashLoopDetector) SaveState() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return json.Marshal(crashLoopSaved{Stops: d.stops, Crashed: d.crashed, State: d.state})
}

func (d *CrashLoopDetector) LoadState(data []byte) error {
	var saved crashLoopSaved
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, v := range saved.Stops {
		d.stops[id] = v
	}
	for id, v := range saved.Crashed {
		d.crashed[id] = v
	}
	for id, st := range saved.State {
		if st == nil || st.Threshold <= 0 || st.Window <= 0 {
			continue
		}
		d.state[id] = st
	}
	return nil
}
