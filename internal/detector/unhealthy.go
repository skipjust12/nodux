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
// Like crashloop, it's both an EventDetector and a poll Detector. The
// daemon emits "health_status: unhealthy" the moment the status flips,
// so the alert doesn't wait for the next poll; the poll keeps the
// episode open and closes it. The event carries no healthcheck output,
// so the engine inspects the container and asks Confirm for the actual
// issue.
//
// An already-unhealthy container is reported on first sight: it's an
// ongoing state, not a past event, so it's still actionable.
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

	msg := "healthcheck failing"
	if s.HealthFailingStreak > 0 {
		msg += fmt.Sprintf(" (%d consecutive failures)", s.HealthFailingStreak)
	}
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

// HandleEvent opens the episode on "health_status: unhealthy". The
// container is assumed running (the daemon doesn't run healthchecks on
// stopped containers); Confirm checks that against inspect.
func (d *UnhealthyDetector) HandleEvent(ev ContainerEvent) *Issue {
	if ev.Action != "health_status" || ev.HealthStatus != "unhealthy" {
		return nil
	}
	return d.Check(ContainerSnapshot{
		ID:           ev.ID,
		Name:         ev.Name,
		Project:      ev.Project,
		Status:       "running",
		HealthStatus: "unhealthy",
	})
}

// Confirm rebuilds the issue from the inspected container, which has the
// failing streak and the last check's output.
func (d *UnhealthyDetector) Confirm(s ContainerSnapshot) *Issue {
	return d.Check(s)
}
