package detector

import (
	"fmt"
	"time"
)

// CrashLoopDetector fires when a container has restarted more than
// threshold times within the sliding window.
//
// Docker doesn't keep a restart history, only a cumulative RestartCount
// since the container was created — so the detector reconstructs the
// history itself: on every poll it looks at the increase in
// RestartCount and records the poll time as the restart time (accurate
// only to within the poll interval).
type CrashLoopDetector struct {
	threshold int
	window    time.Duration
	state     map[string]*crashLoopState
	now       func() time.Time // overridable for tests
}

type crashLoopState struct {
	lastRestartCount int
	events           []time.Time
	lastAlertedCount int
}

func NewCrashLoopDetector(threshold int, window time.Duration) *CrashLoopDetector {
	return &CrashLoopDetector{
		threshold: threshold,
		window:    window,
		state:     make(map[string]*crashLoopState),
		now:       time.Now,
	}
}

func (d *CrashLoopDetector) Name() string { return "crashloop" }

func (d *CrashLoopDetector) Check(s ContainerSnapshot) *Issue {
	now := d.now()

	st, ok := d.state[s.ID]
	if !ok {
		// First time we see this container — just record the baseline;
		// restarts that happened before the daemon started are unknown to us.
		d.state[s.ID] = &crashLoopState{
			lastRestartCount: s.RestartCount,
			lastAlertedCount: -1,
		}
		return nil
	}

	if s.RestartCount > st.lastRestartCount {
		delta := s.RestartCount - st.lastRestartCount
		for i := 0; i < delta; i++ {
			st.events = append(st.events, now)
		}
		st.lastRestartCount = s.RestartCount
	}

	cutoff := now.Add(-d.window)
	kept := st.events[:0]
	for _, t := range st.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.events = kept

	if len(st.events) < d.threshold {
		return nil
	}
	if st.lastAlertedCount == s.RestartCount {
		// Already alerted on this run of restarts, wait for the next one.
		return nil
	}
	st.lastAlertedCount = s.RestartCount

	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityCritical,
		Message:    fmt.Sprintf("container restarted %d times in the last %s", len(st.events), d.window),
		Container:  s,
		DetectedAt: now,
	}
}

func (d *CrashLoopDetector) Forget(containerID string) {
	delete(d.state, containerID)
}
