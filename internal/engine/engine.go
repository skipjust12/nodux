// Package engine wires the docker client, detectors, actions, and the
// LLM stub together into a single poll loop.
package engine

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/llm"
)

const (
	logsTail       = 20
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
)

type Engine struct {
	docker            *dockerclient.Client
	detectors         []detector.Detector
	actions           []action.Action
	classifier        llm.Classifier
	pollInterval      time.Duration
	excludeContainers map[string]struct{}
}

func New(
	docker *dockerclient.Client,
	detectors []detector.Detector,
	actions []action.Action,
	classifier llm.Classifier,
	pollInterval time.Duration,
	excludeContainers []string,
) *Engine {
	exclude := make(map[string]struct{}, len(excludeContainers))
	for _, name := range excludeContainers {
		exclude[name] = struct{}{}
	}
	return &Engine{
		docker:            docker,
		detectors:         detectors,
		actions:           actions,
		classifier:        classifier,
		pollInterval:      pollInterval,
		excludeContainers: exclude,
	}
}

// Run drives the poll loop until ctx is cancelled. Docker socket
// connection errors don't crash the daemon — they're logged, and
// polling is retried with exponential backoff.
func (e *Engine) Run(ctx context.Context) {
	backoff := initialBackoff

	for {
		if ctx.Err() != nil {
			return
		}

		if err := e.pollOnce(ctx); err != nil {
			slog.Error("poll failed, will retry", "error", err, "retry_in", backoff.String())
			if !sleep(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		backoff = initialBackoff
		if !sleep(ctx, e.pollInterval) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (e *Engine) pollOnce(ctx context.Context) error {
	if err := e.docker.Ping(ctx); err != nil {
		return err
	}

	summaries, err := e.docker.ListContainers(ctx)
	if err != nil {
		return err
	}

	for _, summary := range summaries {
		name := containerName(summary)
		if _, excluded := e.excludeContainers[name]; excluded {
			continue
		}

		inspect, err := e.docker.InspectContainer(ctx, summary.ID)
		if err != nil {
			slog.Warn("inspect failed, skipping container this round", "container", name, "error", err)
			continue
		}

		snapshot := toSnapshot(name, inspect)
		e.runDetectors(ctx, summary.ID, inspect.Config.Tty, snapshot)
	}

	return nil
}

func (e *Engine) runDetectors(ctx context.Context, containerID string, tty bool, snapshot detector.ContainerSnapshot) {
	for _, d := range e.detectors {
		issue := d.Check(snapshot)
		if issue == nil {
			continue
		}

		logs, err := e.docker.ContainerLogs(ctx, containerID, logsTail, tty)
		if err != nil {
			slog.Warn("fetch logs failed", "container", snapshot.Name, "error", err)
		}
		issue.Logs = logs

		for _, a := range e.actions {
			if err := a.Run(ctx, *issue); err != nil {
				slog.Error("action failed", "action", a.Name(), "container", snapshot.Name, "error", err)
			}
		}

		if err := e.classifier.Classify(ctx, *issue); err != nil {
			slog.Warn("llm classification failed", "container", snapshot.Name, "error", err)
		}
	}
}

func containerName(s dockerclient.ContainerSummary) string {
	if len(s.Names) == 0 {
		return s.ID
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

func toSnapshot(name string, inspect *dockerclient.ContainerInspect) detector.ContainerSnapshot {
	return detector.ContainerSnapshot{
		ID:           inspect.ID,
		Name:         name,
		Status:       inspect.State.Status,
		RestartCount: inspect.RestartCount,
		ExitCode:     inspect.State.ExitCode,
		OOMKilled:    inspect.State.OOMKilled,
		StartedAt:    parseTime(inspect.State.StartedAt),
		FinishedAt:   parseTime(inspect.State.FinishedAt),
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
