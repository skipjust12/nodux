package detector

import (
	"encoding/json"
	"fmt"
	"time"
)

// MemoryDetector fires when a container's memory usage stays at or
// above threshold percent of its memory limit for at least `sustain`.
// It's the early warning for the oom detector: by the time the OOM
// killer runs, it's too late. The episode ends once usage drops 5
// points below the threshold.
//
// Containers without a memory limit are skipped. Their "limit" is the
// host's RAM, which is what the host_memory detector checks.
//
// nodux.memory.threshold and nodux.memory.for override the defaults per
// container. Only the poll loop touches it, so it needs no lock.
type MemoryDetector struct {
	threshold float64
	sustain   time.Duration
	state     map[string]*gate
	now       func() time.Time
}

func NewMemoryDetector(thresholdPercent float64, sustain time.Duration) *MemoryDetector {
	return &MemoryDetector{
		threshold: thresholdPercent,
		sustain:   sustain,
		state:     make(map[string]*gate),
		now:       time.Now,
	}
}

func (d *MemoryDetector) Name() string { return "memory" }

func (d *MemoryDetector) Check(s ContainerSnapshot) *Issue {
	g := d.state[s.ID]
	if s.MemoryLimit == 0 {
		// Stats are only collected for running containers. One that
		// stopped mid-episode (likely OOM-killed) stays in it until it
		// runs again and we can measure; one without a limit is out.
		if g != nil && g.firing && s.Status != "running" {
			return d.issue(s, "memory limit reached before the container stopped")
		}
		delete(d.state, s.ID)
		return nil
	}

	if g == nil {
		g = &gate{threshold: d.threshold, sustain: d.sustain}
		if pct, ok := labelPercent(s.Labels, "nodux.memory.threshold"); ok {
			g.threshold = pct
		}
		if sustain, ok := labelDuration(s.Labels, "nodux.memory.for"); ok {
			g.sustain = sustain
		}
		d.state[s.ID] = g
	}
	pct := float64(s.MemoryUsed) / float64(s.MemoryLimit) * 100
	if !g.update(d.now(), pct) {
		return nil
	}

	msg := fmt.Sprintf("memory at %.0f%% of limit (%s / %s)", pct, formatBytes(s.MemoryUsed), formatBytes(s.MemoryLimit))
	if g.sustain > 0 {
		msg += fmt.Sprintf(" for at least %s", g.sustain)
	}
	return d.issue(s, msg)
}

func (d *MemoryDetector) issue(s ContainerSnapshot, msg string) *Issue {
	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Container:  s,
		DetectedAt: d.now(),
	}
}

func (d *MemoryDetector) Forget(containerID string) {
	delete(d.state, containerID)
}

// Only firing gates are saved: one that was merely above the threshold
// starts its for_seconds over, since nodux didn't see what happened
// while it was down.
type savedGate struct {
	Threshold float64       `json:"threshold"`
	Sustain   time.Duration `json:"sustain"`
}

func (d *MemoryDetector) SaveState() ([]byte, error) {
	firing := make(map[string]savedGate)
	for id, g := range d.state {
		if g.firing {
			firing[id] = savedGate{Threshold: g.threshold, Sustain: g.sustain}
		}
	}
	return json.Marshal(firing)
}

func (d *MemoryDetector) LoadState(data []byte) error {
	var firing map[string]savedGate
	if err := json.Unmarshal(data, &firing); err != nil {
		return err
	}
	for id, g := range firing {
		d.state[id] = &gate{threshold: g.Threshold, sustain: g.Sustain, firing: true}
	}
	return nil
}

// FormatBytes renders a byte count the way people read them: 1.5GiB.
func FormatBytes(b uint64) string { return formatBytes(b) }

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
