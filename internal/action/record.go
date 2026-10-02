package action

import (
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	StateFiring   = "firing"
	StateResolved = "resolved"

	KindAlert  = "alert"
	KindDigest = "digest"
)

// Record is the wire format of an alert, shared by every action that
// emits JSON (console, webhook) so consumers see one schema.
//
// Container fields are only present for container alerts; host-level
// alerts (host_disk, docker, ...) carry a resource instead.
type Record struct {
	Kind          string   `json:"kind"` // alert
	Timestamp     string   `json:"timestamp"`
	State         string   `json:"state"` // firing or resolved
	Host          string   `json:"host,omitempty"`
	Detector      string   `json:"detector"`
	Severity      string   `json:"severity"`
	Message       string   `json:"message"`
	IncidentID    int64    `json:"incident_id,omitempty"`
	Resource      string   `json:"resource,omitempty"`
	ContainerID   string   `json:"container_id,omitempty"`
	ContainerName string   `json:"container_name,omitempty"`
	Image         string   `json:"image,omitempty"`
	Status        string   `json:"status,omitempty"`
	RestartCount  *int     `json:"restart_count,omitempty"`
	LastExitCode  *int     `json:"last_exit_code,omitempty"`
	OOMKilled     bool     `json:"oom_killed,omitempty"`
	HealthStatus  string   `json:"health_status,omitempty"`
	MemoryUsed    uint64   `json:"memory_used_bytes,omitempty"`
	MemoryLimit   uint64   `json:"memory_limit_bytes,omitempty"`
	Silenced      bool     `json:"silenced,omitempty"`
	Analysis      string   `json:"analysis,omitempty"`
	Logs          []string `json:"logs,omitempty"`
}

func NewRecord(issue detector.Issue) Record {
	c := issue.Container
	r := Record{
		Kind:          KindAlert,
		Timestamp:     issue.DetectedAt.UTC().Format(time.RFC3339),
		State:         StateFiring,
		Host:          issue.Host,
		Detector:      issue.Detector,
		Severity:      issue.Severity,
		Message:       issue.Message,
		IncidentID:    issue.IncidentID,
		Resource:      issue.Resource,
		ContainerID:   c.ID,
		ContainerName: c.Name,
		Image:         c.Image,
		Status:        c.Status,
		OOMKilled:     c.OOMKilled,
		HealthStatus:  c.HealthStatus,
		MemoryUsed:    c.MemoryUsed,
		MemoryLimit:   c.MemoryLimit,
		Silenced:      issue.Silenced,
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

// DigestRecord is the wire format of a digest.
type DigestRecord struct {
	Kind      string `json:"kind"` // digest
	Timestamp string `json:"timestamp"`
	Host      string `json:"host,omitempty"`
	Title     string `json:"title"`
	From      string `json:"from"`
	To        string `json:"to"`
	Text      string `json:"text"`
	Data      any    `json:"data,omitempty"`
}

func NewDigestRecord(d *Digest) DigestRecord {
	return DigestRecord{
		Kind:      KindDigest,
		Timestamp: d.To.UTC().Format(time.RFC3339),
		Host:      d.Host,
		Title:     d.Title,
		From:      d.From.UTC().Format(time.RFC3339),
		To:        d.To.UTC().Format(time.RFC3339),
		Text:      d.Text,
		Data:      d.Data,
	}
}
