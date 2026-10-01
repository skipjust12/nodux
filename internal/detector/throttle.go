package detector

import (
	"fmt"
	"time"
)

// ThrottleDetector fires when a container keeps running into its CPU
// limit (--cpus, cpu_quota): the share of CFS scheduling periods in
// which it was throttled stays at or above threshold percent for
// sustain. That's the classic "slow but not crashing" container: no
// exit, no OOM, healthchecks may even pass, and requests just take
// longer.
//
// The counters come from the same stats call the memory detector uses
// and are cumulative, so the ratio is taken between consecutive polls.
// Only containers with a CPU limit are checked.
type ThrottleDetector struct {
	threshold float64
	sustain   time.Duration
	state     map[string]*throttleState
	now       func() time.Time
}

type throttleState struct {
	gate      gate
	periods   uint64
	throttled uint64
	lastPct   float64
}

func NewThrottleDetector(thresholdPercent float64, sustain time.Duration) *ThrottleDetector {
	return &ThrottleDetector{
		threshold: thresholdPercent,
		sustain:   sustain,
		state:     make(map[string]*throttleState),
		now:       time.Now,
	}
}

func (d *ThrottleDetector) Name() string { return "cpu_throttle" }

func (d *ThrottleDetector) Check(s ContainerSnapshot) *Issue {
	if s.CPULimit == 0 {
		// Not running, or no limit: nothing is being throttled.
		delete(d.state, s.ID)
		return nil
	}
	st := d.state[s.ID]
	if st == nil {
		d.state[s.ID] = &throttleState{
			gate:      gate{threshold: d.threshold, sustain: d.sustain},
			periods:   s.CPUPeriods,
			throttled: s.CPUThrottledPeriods,
		}
		return nil
	}

	dp, dt := s.CPUPeriods-st.periods, s.CPUThrottledPeriods-st.throttled
	if s.CPUPeriods < st.periods || s.CPUThrottledPeriods < st.throttled {
		// Counters reset: the container restarted between polls.
		dp, dt = 0, 0
	}
	st.periods, st.throttled = s.CPUPeriods, s.CPUThrottledPeriods

	var pct float64
	if dp > 0 {
		pct = float64(dt) / float64(dp) * 100
	} else if st.gate.firing && s.CPUPeriods > 0 {
		// Idle since the last poll: no periods ran, so no new evidence
		// either way. Keep the current state.
		pct = st.lastPct
	}
	st.lastPct = pct
	if !st.gate.update(d.now(), pct) {
		return nil
	}

	msg := fmt.Sprintf("CPU throttled in %.0f%% of scheduling periods at a limit of %s", pct, formatCPUs(s.CPULimit))
	if d.sustain > 0 {
		msg += fmt.Sprintf(" for at least %s", d.sustain)
	}
	msg += ": the container needs more CPU than it's allowed"
	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Container:  s,
		DetectedAt: d.now(),
	}
}

func (d *ThrottleDetector) Forget(containerID string) {
	delete(d.state, containerID)
}

func formatCPUs(n float64) string {
	if n == 1 {
		return "1 CPU"
	}
	return fmt.Sprintf("%g CPUs", n)
}
