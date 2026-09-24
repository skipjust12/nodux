// Package detector defines the common contract for all container
// problem detectors. There are two kinds:
//
//   - Detector looks at a snapshot of container state taken at poll time.
//     Good for conditions that persist (restart counts, health status).
//   - EventDetector reacts to the daemon's event stream. Needed for
//     things that are gone by the next poll: e.g. Docker resets
//     State.OOMKilled as soon as a restart policy brings the container
//     back up, so an OOM in a restarting container is only reliably
//     visible as an "oom" event.
//
// Fetching logs and dispatching actions is the engine's job, not the
// detector's.
package detector

import "time"

// ContainerSnapshot is a container's state at poll time, assembled
// from docker inspect.
type ContainerSnapshot struct {
	ID           string
	Name         string
	Status       string // running, exited, restarting, ...
	RestartCount int
	ExitCode     int
	OOMKilled    bool
	StartedAt    time.Time
	FinishedAt   time.Time

	// Health is empty when the container has no healthcheck.
	HealthStatus        string // starting, healthy, unhealthy
	HealthFailingStreak int
	HealthLastOutput    string
}

// ContainerEvent is a container lifecycle event from the daemon.
type ContainerEvent struct {
	ID       string
	Name     string
	Action   string // start, kill, oom, die, destroy
	ExitCode int    // only meaningful for "die"
	Time     time.Time
}

// Issue is a detected problem. Logs is filled in by the engine after
// the detector returns the issue, so we don't fetch logs for containers
// that are perfectly healthy.
type Issue struct {
	Detector   string
	Severity   string
	Message    string
	Container  ContainerSnapshot
	DetectedAt time.Time
	Logs       []string
}

const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Detector is the interface every snapshot-based detector implements.
// Check is called on every poll for every non-excluded container;
// the detector decides for itself whether it needs to keep state
// between calls.
type Detector interface {
	Name() string
	Check(snapshot ContainerSnapshot) *Issue
}

// EventDetector is the interface for detectors driven by the event
// stream. HandleEvent is called for every container event nodux
// subscribes to (see Actions), in the order the daemon emits them. The
// returned Issue only needs Container.ID/Name and whatever fields the
// event itself carries; the engine fills in the rest from inspect.
type EventDetector interface {
	Name() string
	HandleEvent(ev ContainerEvent) *Issue
}

// Forgetter is implemented by stateful snapshot detectors so the engine
// can drop state for containers that no longer exist.
type Forgetter interface {
	Forget(containerID string)
}

// EventActions are the event types event detectors are fed.
var EventActions = []string{"start", "kill", "oom", "die", "destroy"}
