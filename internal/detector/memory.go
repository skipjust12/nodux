package detector

import (
	"fmt"
	"time"
)

// memoryRearmGap is the hysteresis: after an alert, usage has to drop
// this many percentage points below the threshold before a new alert
// can fire, so a container hovering around the threshold doesn't flap.
const memoryRearmGap = 5.0

// MemoryDetector fires when a container's memory usage stays at or
// above threshold percent of its memory limit for at least `sustain`.
// It's the early warning for the oom detector: by the time the OOM
// killer runs, it's too late.
//
// Containers without a memory limit are skipped. Their "limit" is the
// host's RAM, which is a host-level check, not a per-container one.
type MemoryDetector struct {
	threshold float64
	sustain   time.Duration
	state     map[string]*memoryState
	now       func() time.Time
}

type memoryState struct {
	aboveSince time.Time // zero = currently below threshold
	alerted    bool
}

func NewMemoryDetector(thresholdPercent float64, sustain time.Duration) *MemoryDetector {
	return &MemoryDetector{
		threshold: thresholdPercent,
		sustain:   sustain,
		state:     make(map[string]*memoryState),
		now:       time.Now,
	}
}

func (d *MemoryDetector) Name() string { return "memory" }

func (d *MemoryDetector) Check(s ContainerSnapshot) *Issue {
	if s.MemoryLimit == 0 {
		delete(d.state, s.ID)
		return nil
	}

	now := d.now()
	pct := float64(s.MemoryUsed) / float64(s.MemoryLimit) * 100

	st, ok := d.state[s.ID]
	if !ok {
		st = &memoryState{}
		d.state[s.ID] = st
	}

	if pct < d.threshold {
		st.aboveSince = time.Time{}
		if pct < d.threshold-memoryRearmGap {
			st.alerted = false
		}
		return nil
	}

	if st.aboveSince.IsZero() {
		st.aboveSince = now
	}
	if st.alerted || now.Sub(st.aboveSince) < d.sustain {
		return nil
	}
	st.alerted = true

	msg := fmt.Sprintf("memory at %.0f%% of limit (%s / %s)", pct, formatBytes(s.MemoryUsed), formatBytes(s.MemoryLimit))
	if d.sustain > 0 {
		msg += fmt.Sprintf(" for at least %s", d.sustain)
	}
	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Container:  s,
		DetectedAt: now,
	}
}

func (d *MemoryDetector) Forget(containerID string) {
	delete(d.state, containerID)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
