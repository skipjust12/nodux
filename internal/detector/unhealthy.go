package detector

import (
	"fmt"
	"strings"
	"time"
)

const maxHealthOutput = 300

// UnhealthyDetector fires when a container's healthcheck reports
// "unhealthy". It alerts once per unhealthy episode: the next alert only
// comes after the container has been seen healthy (or starting) again.
//
// Unlike crashloop, an already-unhealthy container is reported on first
// sight: it's an ongoing state, not a past event, so it's still actionable.
type UnhealthyDetector struct {
	alerted map[string]bool
	now     func() time.Time
}

func NewUnhealthyDetector() *UnhealthyDetector {
	return &UnhealthyDetector{alerted: make(map[string]bool), now: time.Now}
}

func (d *UnhealthyDetector) Name() string { return "unhealthy" }

func (d *UnhealthyDetector) Check(s ContainerSnapshot) *Issue {
	if s.HealthStatus != "unhealthy" {
		delete(d.alerted, s.ID)
		return nil
	}
	if d.alerted[s.ID] {
		return nil
	}
	d.alerted[s.ID] = true

	msg := fmt.Sprintf("healthcheck failing (%d consecutive failures)", s.HealthFailingStreak)
	if out := truncate(strings.TrimSpace(s.HealthLastOutput), maxHealthOutput); out != "" {
		msg += ": " + out
	}

	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Container:  s,
		DetectedAt: d.now(),
	}
}

func (d *UnhealthyDetector) Forget(containerID string) {
	delete(d.alerted, containerID)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
