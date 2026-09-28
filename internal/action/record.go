package action

import (
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	StateFiring   = "firing"
	StateResolved = "resolved"
)

// Record is the wire format of an alert, shared by every action that
// emits JSON (console, webhook) so consumers see one schema.
//
// Container fields are only present for container alerts; host-level
// alerts (host_disk, docker, ...) carry a resource instead.
type Record struct {
	Timestamp     string   `json:"timestamp"`
	State         string   `json:"state"` // firing or resolved
	Host          string   `json:"host,omitempty"`
	Detector      string   `json:"detector"`
	Severity      string   `json:"severity"`
	Message       string   `json:"message"`
	Resource      string   `json:"resource,omitempty"`
	ContainerID   string   `json:"container_id,omitempty"`
	ContainerName string   `json:"container_name,omitempty"`
	Status        string   `json:"status,omitempty"`
	RestartCount  *int     `json:"restart_count,omitempty"`
	LastExitCode  *int     `json:"last_exit_code,omitempty"`
	OOMKilled     bool     `json:"oom_killed,omitempty"`
	HealthStatus  string   `json:"health_status,omitempty"`
	MemoryUsed    uint64   `json:"memory_used_bytes,omitempty"`
	MemoryLimit   uint64   `json:"memory_limit_bytes,omitempty"`
	Analysis      string   `json:"analysis,omitempty"`
	Logs          []string `json:"logs,omitempty"`
}

func NewRecord(issue detector.Issue) Record {
	c := issue.Container
	r := Record{
		Timestamp:     issue.DetectedAt.UTC().Format(time.RFC3339),
		State:         StateFiring,
		Host:          issue.Host,
		Detector:      issue.Detector,
		Severity:      issue.Severity,
		Message:       issue.Message,
		Resource:      issue.Resource,
		ContainerID:   c.ID,
		ContainerName: c.Name,
		Status:        c.Status,
		OOMKilled:     c.OOMKilled,
		HealthStatus:  c.HealthStatus,
		MemoryUsed:    c.MemoryUsed,
		MemoryLimit:   c.MemoryLimit,
		Analysis:      issue.Analysis,
		Logs:          issue.Logs,
	}
	if issue.Resolved {
		r.State = StateResolved
	}
	if c.ID != "" {
		restarts, exit := c.RestartCount, c.ExitCode
		r.RestartCount, r.LastExitCode = &restarts, &exit
	}
	return r
}
