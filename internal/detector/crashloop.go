package detector

import (
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
	restarts []time.Time
	firing   bool
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
			st = &crashLoopState{}
			d.state[ev.ID] = st
		}
		st.restarts = append(st.restarts, ev.Time)
		st.prune(ev.Time.Add(-d.window))
		if st.firing || len(st.restarts) < d.threshold {
			return nil
		}
		st.firing = true
		return d.issue(ContainerSnapshot{ID: ev.ID, Name: ev.Name, ExitCode: exitCode}, len(st.restarts), ev.Time)
	}
	return nil
}

func (d *CrashLoopDetector) Check(s ContainerSnapshot) *Issue {
	d.mu.Lock()
	defer d.mu.Unlock()

	st := d.state[s.ID]
	if st == nil {
		return nil
	}
	now := d.now()
	st.prune(now.Add(-d.window))

	if !st.firing {
		if len(st.restarts) < d.threshold {
			if len(st.restarts) == 0 {
				delete(d.state, s.ID)
			}
			return nil
		}
		st.firing = true
	}
	if len(st.restarts) == 0 && s.Status == "running" {
		delete(d.state, s.ID)
		return nil
	}
	return d.issue(s, len(st.restarts), now)
}

func (d *CrashLoopDetector) issue(s ContainerSnapshot, restarts int, at time.Time) *Issue {
	msg := fmt.Sprintf("container restarted %d times in the last %s after crashing", restarts, d.window)
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
	kept := st.restarts[:0]
	for _, t := range st.restarts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.restarts = kept
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
