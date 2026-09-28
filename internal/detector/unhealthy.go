package detector

import (
	"fmt"
	"strings"
	"time"
)

const maxHealthOutput = 300

// UnhealthyDetector fires while a container's healthcheck reports
// "unhealthy". The episode ends when Docker reports it healthy (or
// starting, after a restart) again.
//
// Unlike crashloop, an already-unhealthy container is reported on first
// sight: it's an ongoing state, not a past event, so it's still actionable.
//
// Only running containers count: Docker marks a container with a
// healthcheck unhealthy when it stops, including on a plain docker stop.
// A container that shouldn't have stopped is exit's or expected's to
// report.
type UnhealthyDetector struct{}

func NewUnhealthyDetector() *UnhealthyDetector { return &UnhealthyDetector{} }

func (d *UnhealthyDetector) Name() string { return "unhealthy" }

func (d *UnhealthyDetector) Check(s ContainerSnapshot) *Issue {
	if s.HealthStatus != "unhealthy" || s.Status != "running" {
		return nil
	}

	msg := fmt.Sprintf("healthcheck failing (%d consecutive failures)", s.HealthFailingStreak)
	if out := Truncate(strings.TrimSpace(s.HealthLastOutput), maxHealthOutput); out != "" {
		msg += ": " + out
	}

	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Container:  s,
		DetectedAt: time.Now(),
	}
}
