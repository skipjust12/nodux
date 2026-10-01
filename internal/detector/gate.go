package detector

import "time"

// rearmGap is the hysteresis for threshold detectors: once firing, the
// value has to drop this many points below the threshold before the
// problem counts as over, so something hovering around the threshold
// doesn't flap between alert and resolution.
const rearmGap = 5.0

// gate turns a stream of percentages into a firing state: it opens once
// the value has stayed at or above threshold for sustain, and closes
// once it drops below threshold - rearmGap. For thresholds under 10 the
// gap is half the threshold, so a low threshold (a PSI stall of 4%)
// can still close.
type gate struct {
	threshold  float64
	sustain    time.Duration
	aboveSince time.Time // zero = currently below threshold
	firing     bool
}

func (g *gate) update(now time.Time, value float64) bool {
	if g.firing {
		if value < g.threshold-min(rearmGap, g.threshold/2) {
			g.firing = false
			g.aboveSince = time.Time{}
		}
		return g.firing
	}
	if value < g.threshold {
		g.aboveSince = time.Time{}
		return false
	}
	if g.aboveSince.IsZero() {
		g.aboveSince = now
	}
	g.firing = now.Sub(g.aboveSince) >= g.sustain
	return g.firing
}
