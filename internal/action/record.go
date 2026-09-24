package action

import (
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

// Record is the wire format of an alert, shared by every action that
// emits JSON (console, webhook) so consumers see one schema.
type Record struct {
	Timestamp     string   `json:"timestamp"`
	Detector      string   `json:"detector"`
	Severity      string   `json:"severity"`
	Message       string   `json:"message"`
	ContainerID   string   `json:"container_id"`
	ContainerName string   `json:"container_name"`
	Status        string   `json:"status,omitempty"`
	RestartCount  int      `json:"restart_count"`
	LastExitCode  int      `json:"last_exit_code"`
	OOMKilled     bool     `json:"oom_killed,omitempty"`
	HealthStatus  string   `json:"health_status,omitempty"`
	MemoryUsed    uint64   `json:"memory_used_bytes,omitempty"`
	MemoryLimit   uint64   `json:"memory_limit_bytes,omitempty"`
	Logs          []string `json:"logs"`
}

func NewRecord(issue detector.Issue) Record {
	return Record{
		Timestamp:     issue.DetectedAt.UTC().Format(time.RFC3339),
		Detector:      issue.Detector,
		Severity:      issue.Severity,
		Message:       issue.Message,
		ContainerID:   issue.Container.ID,
		ContainerName: issue.Container.Name,
		Status:        issue.Container.Status,
		RestartCount:  issue.Container.RestartCount,
		LastExitCode:  issue.Container.ExitCode,
		OOMKilled:     issue.Container.OOMKilled,
		HealthStatus:  issue.Container.HealthStatus,
		MemoryUsed:    issue.Container.MemoryUsed,
		MemoryLimit:   issue.Container.MemoryLimit,
		Logs:          issue.Logs,
	}
}
