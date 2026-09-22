// Package detector defines the common contract for all container
// problem detectors. Each detector gets a snapshot of container state
// taken at poll time and decides whether there's a problem; fetching
// logs and dispatching actions is the engine's job, not the detector's.
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

// Detector is the interface every problem detector must implement.
// Check is called on every poll for every non-excluded container;
// the detector decides for itself whether it needs to keep state
// between calls.
type Detector interface {
	Name() string
	Check(snapshot ContainerSnapshot) *Issue
}
