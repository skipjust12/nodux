package action

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

// ConsoleAction prints a detected problem to stdout as a single JSON
// line, so it can later be shipped anywhere (journald, Loki, a file, ...).
type ConsoleAction struct{}

func NewConsole() *ConsoleAction { return &ConsoleAction{} }

func (a *ConsoleAction) Name() string { return "console" }

type consoleRecord struct {
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
	Logs          []string `json:"logs"`
}

func (a *ConsoleAction) Run(_ context.Context, issue detector.Issue) error {
	rec := consoleRecord{
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
		Logs:          issue.Logs,
	}

	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal issue: %w", err)
	}
	fmt.Println(string(b))
	return nil
}
