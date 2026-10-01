// Package detector defines the common contract for all problem
// detectors. There are three kinds:
//
//   - Detector looks at a snapshot of container state taken at poll
//     time. It's level-triggered: Check returns an Issue for as long as
//     the problem lasts and nil once it's over. The engine alerts when a
//     problem starts and sends a resolution when it ends, so detectors
//     don't need to deduplicate.
//   - EventDetector reacts to the daemon's event stream. Needed for
//     things that are gone by the next poll: e.g. Docker resets
//     State.OOMKilled as soon as a restart policy brings the container
//     back up, so an OOM in a restarting container is only reliably
//     visible as an "oom" event. Its issues are one-off alerts.
//   - HostDetector checks the host itself (disk, memory, CPU, pressure)
//     or something outside it (probes), also level-triggered, returning
//     every problem that currently holds.
//
// Fetching logs and dispatching actions is the engine's job, not the
// detector's.
package detector

import (
	"time"
	"unicode/utf8"
)

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
	// Project is the compose project (com.docker.compose.project label),
	// empty for containers not started by compose.
	Project string
	// Tty says how to read the container's logs (raw vs multiplexed).
	Tty bool

	// Health is empty when the container has no healthcheck.
	HealthStatus        string // starting, healthy, unhealthy
	HealthFailingStreak int
	HealthLastOutput    string

	// Memory is only filled in for running containers with a memory
	// limit, and only when a detector needs it. Limit 0 = not collected.
	MemoryUsed  uint64
	MemoryLimit uint64

	// CPU throttling counters (cumulative since the container started),
	// only filled in for running containers with a CPU limit, and only
	// when a detector needs them. CPULimit 0 = not collected.
	CPULimit            float64 // in CPUs, e.g. 0.5 for --cpus 0.5
	CPUPeriods          uint64
	CPUThrottledPeriods uint64
}

// ContainerEvent is a container lifecycle event from the daemon.
type ContainerEvent struct {
	ID     string
	Name   string
	Action string // create, start, kill, oom, die, destroy, health_status
	// Project is the compose project label, if any.
	Project string
	// HealthStatus is the new status of a health_status event.
	HealthStatus string
	ExitCode     int // only meaningful for "die"
	// Signal is the signal a "kill" event delivered, 0 if unknown.
	Signal int
	// StopSignal is the container's configured stop signal (what docker
	// stop sends first), 0 if unknown. Only filled in for "kill".
	StopSignal int
	Time       time.Time
}

// Issue is a detected problem, or the resolution of one. Logs is
// filled in by the engine after the detector returns the issue, so we
// don't fetch logs for containers that are perfectly healthy.
type Issue struct {
	Detector string
	Severity string
	Message  string
	// Container is zero for host-level issues.
	Container ContainerSnapshot
	// Resource names what a host-level issue is about (e.g. a mount
	// point). Empty for container issues.
	Resource   string
	Host       string
	DetectedAt time.Time
	Logs       []string
	// Analysis is the optional LLM layer's take on the probable cause.
	Analysis string
	// Resolved marks the "problem is over" notification that follows a
	// level-triggered alert.
	Resolved bool
	// Silenced alerts are logged locally but not sent to receivers.
	Silenced bool
}

const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Detector is the interface every snapshot-based detector implements.
// Check is called on every poll for every non-excluded container and
// returns an Issue for as long as the problem lasts.
type Detector interface {
	Name() string
	Check(snapshot ContainerSnapshot) *Issue
}

// EventDetector is the interface for detectors driven by the event
// stream. HandleEvent is called for every container event nodux
// subscribes to (see EventActions), in the order the daemon emits them.
// The returned Issue only needs Container.ID/Name and whatever fields
// the event itself carries; the engine fills in the rest from inspect.
//
// A detector may implement both Detector and EventDetector (crashloop
// does). Then an issue returned from HandleEvent opens the same
// level-triggered episode that Check keeps alive and eventually ends.
type EventDetector interface {
	Name() string
	HandleEvent(ev ContainerEvent) *Issue
}

// Confirmer is implemented by event detectors whose events only say
// "look at this container now": a health_status event carries no
// healthcheck output. The engine inspects the container and replaces
// the event's issue with Confirm's verdict on the full snapshot; nil
// drops it.
type Confirmer interface {
	Confirm(s ContainerSnapshot) *Issue
}

// HostDetector checks something about the host rather than a
// container. Check returns every problem that currently holds; each
// Issue must have a Resource that identifies it across calls.
type HostDetector interface {
	Name() string
	Check() []*Issue
}

// Forgetter is implemented by stateful snapshot detectors so the engine
// can drop state for containers that no longer exist.
type Forgetter interface {
	Forget(containerID string)
}

// EventActions are the event types nodux subscribes to. The daemon
// matches "health_status" against "health_status: unhealthy" and
// friends. "create" is only used to spot deploys.
var EventActions = []string{"create", "start", "kill", "oom", "die", "destroy", "health_status"}

// SeverityRank orders severities: a higher rank is more urgent.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	}
	return 0
}

// Truncate cuts s to at most n bytes without splitting a UTF-8
// sequence, marking the cut with "…".
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
