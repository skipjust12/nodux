// Package tools is what the LLM layer may look at on its own: a fixed
// set of read-only tools over the Docker API, the host's /proc and
// nodux's alert history. Nothing here can change anything: no exec, no
// writes, only GET requests and file reads. Every result is redacted
// before the model sees it, containers nodux is told to ignore are
// invisible, and output is kept short.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
)

const (
	maxLogLines   = 300
	defLogLines   = 100
	maxLineBytes  = 500
	maxScanLines  = 2000 // lines scanned for a "contains" filter
	maxHistory    = 50
	maxTopRows    = 15
	maxListed     = 40
	maxHistoryHrs = 24 * 30
)

type Config struct {
	Docker   *dockerclient.Client
	History  *history.Store // nil: no alert history
	Redactor *redact.Redactor
	ProcPath string
	// DiskPaths are the filesystems host_overview reports on.
	DiskPaths []string
	// Exclude are container names nodux ignores; so does the model.
	Exclude []string
	// OpenAlerts lists the alerts open right now.
	OpenAlerts func() []detector.Issue
}

type Toolbox struct {
	cfg     Config
	exclude map[string]bool
	now     func() time.Time
	// cpuSample is how long host_overview watches per-process CPU.
	cpuSample time.Duration
}

func New(cfg Config) *Toolbox {
	if cfg.ProcPath == "" {
		cfg.ProcPath = "/proc"
	}
	ex := make(map[string]bool, len(cfg.Exclude))
	for _, n := range cfg.Exclude {
		ex[n] = true
	}
	return &Toolbox{cfg: cfg, exclude: ex, now: time.Now, cpuSample: time.Second}
}

var nameProp = map[string]any{
	"type":        "string",
	"description": "Container name, compose service name, or ID prefix.",
}

func (t *Toolbox) Tools() []llm.ToolSpec {
	specs := []llm.ToolSpec{
		{
			Name:        "list_containers",
			Description: "List the containers on this host: name, image, state and status (uptime, exit code, health), and compose project/service.",
		},
		{
			Name:        "inspect_container",
			Description: "A container's configuration and state: image, when it was created and started, restart count and policy, exit code, OOM flag, recent healthcheck results, memory and CPU limits, command, names of the environment variables it sets (not their values), mounts and compose labels.",
			Properties:  map[string]any{"name": nameProp},
			Required:    []string{"name"},
		},
		{
			Name:        "container_logs",
			Description: "A container's log lines (stdout and stderr), each prefixed with the time it was logged. Narrow it to a time range around an event, or to lines containing a string.",
			Properties: map[string]any{
				"name":     nameProp,
				"since":    map[string]any{"type": "string", "description": "Start of the range: an RFC 3339 time, or how long ago, like 15m or 2h."},
				"until":    map[string]any{"type": "string", "description": "End of the range, same format as since."},
				"tail":     map[string]any{"type": "integer", "description": fmt.Sprintf("Return at most this many of the last matching lines (default %d, max %d).", defLogLines, maxLogLines)},
				"contains": map[string]any{"type": "string", "description": "Only lines containing this text (case-insensitive)."},
			},
			Required: []string{"name"},
		},
		{
			Name:        "container_stats",
			Description: "Live resource use of a running container: CPU (measured over about a second), memory against its limit, CPU throttling, process count, network and block I/O totals, and its processes.",
			Properties:  map[string]any{"name": nameProp},
			Required:    []string{"name"},
		},
		{
			Name:        "docker_disk_usage",
			Description: "What Docker takes up on disk (docker system df): images (and how much no container uses), containers' writable layers, volumes, build cache. Can take a few seconds.",
		},
		{
			Name:        "host_overview",
			Description: "The host: uptime, load, memory and swap, usage of the monitored filesystems, pressure stall information, and the processes using the most memory and CPU.",
		},
	}
	if t.cfg.History != nil || t.cfg.OpenAlerts != nil {
		specs = append(specs, llm.ToolSpec{
			Name:        "alert_history",
			Description: "Alerts that are open right now, and nodux's past alerts, newest first: for one container (or host resource like / or memory), or for everything.",
			Properties: map[string]any{
				"name":  map[string]any{"type": "string", "description": "Container name or host resource; omit for all."},
				"hours": map[string]any{"type": "integer", "description": fmt.Sprintf("How far back to look (default 24, max %d).", maxHistoryHrs)},
			},
		})
	}
	return specs
}

// Call runs a tool. The output is redacted; errors are meant for the
// model too ("no container named x"), so they're redacted as well.
func (t *Toolbox) Call(ctx context.Context, name string, input json.RawMessage) (string, error) {
	out, err := t.call(ctx, name, input)
	if err != nil {
		return "", errors.New(t.cfg.Redactor.String(err.Error()))
	}
	return t.cfg.Redactor.String(out), nil
}

func (t *Toolbox) call(ctx context.Context, name string, input json.RawMessage) (string, error) {
	var in struct {
		Name     string `json:"name"`
		Since    string `json:"since"`
		Until    string `json:"until"`
		Tail     int    `json:"tail"`
		Contains string `json:"contains"`
		Hours    int    `json:"hours"`
	}
	if len(input) > 0 {
		if err := json.Unmarshal(input, &in); err != nil {
			return "", fmt.Errorf("invalid input: %v", err)
		}
	}
	needsName := func() error {
		if strings.TrimSpace(in.Name) == "" {
			return errors.New("name is required")
		}
		return nil
	}

	switch name {
	case "list_containers":
		return t.listContainers(ctx)
	case "inspect_container":
		if err := needsName(); err != nil {
			return "", err
		}
		return t.inspect(ctx, in.Name)
	case "container_logs":
		if err := needsName(); err != nil {
			return "", err
		}
		return t.logs(ctx, in.Name, in.Since, in.Until, in.Tail, in.Contains)
	case "container_stats":
		if err := needsName(); err != nil {
			return "", err
		}
		return t.stats(ctx, in.Name)
	case "docker_disk_usage":
		return t.diskUsage(ctx)
	case "host_overview":
		return t.hostOverview(ctx)
	case "alert_history":
		if t.cfg.History == nil && t.cfg.OpenAlerts == nil {
			break
		}
		return t.alertHistory(ctx, in.Name, in.Hours)
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// visible lists the containers the model may see.
func (t *Toolbox) visible(ctx context.Context) ([]dockerclient.ContainerSummary, error) {
	all, err := t.cfg.Docker.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, c := range all {
		if t.exclude[containerName(c)] || detector.Excluded(c.Labels) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return containerName(out[i]) < containerName(out[j]) })
	return out, nil
}

// resolve finds a container by exact name, ID prefix, compose service
// or, failing those, a unique substring of its name.
func (t *Toolbox) resolve(ctx context.Context, query string) (dockerclient.ContainerSummary, error) {
	query = strings.TrimPrefix(strings.TrimSpace(query), "/")
	list, err := t.visible(ctx)
	if err != nil {
		return dockerclient.ContainerSummary{}, err
	}
	matchers := []func(c dockerclient.ContainerSummary) bool{
		func(c dockerclient.ContainerSummary) bool { return containerName(c) == query },
		func(c dockerclient.ContainerSummary) bool { return len(query) >= 4 && strings.HasPrefix(c.ID, query) },
		func(c dockerclient.ContainerSummary) bool { return c.Labels[detector.LabelComposeService] == query },
		func(c dockerclient.ContainerSummary) bool {
			return strings.Contains(strings.ToLower(containerName(c)), strings.ToLower(query))
		},
	}
	for _, match := range matchers {
		var found []dockerclient.ContainerSummary
		for _, c := range list {
			if match(c) {
				found = append(found, c)
			}
		}
		switch {
		case len(found) == 1:
			return found[0], nil
		case len(found) > 1:
			return dockerclient.ContainerSummary{}, fmt.Errorf("%q matches several containers: %s", query, names(found))
		}
	}
	return dockerclient.ContainerSummary{}, fmt.Errorf("no container matches %q; containers: %s", query, names(list))
}

func names(list []dockerclient.ContainerSummary) string {
	var out []string
	for i, c := range list {
		if i == maxListed {
			out = append(out, fmt.Sprintf("and %d more", len(list)-maxListed))
			break
		}
		out = append(out, containerName(c))
	}
	if len(out) == 0 {
		return "(none)"
	}
	return strings.Join(out, ", ")
}

func containerName(c dockerclient.ContainerSummary) string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	if t.Year() <= 1 {
		return time.Time{}
	}
	return t
}

// parseWhen takes an RFC 3339 time or a duration ago ("15m").
func (t *Toolbox) parseWhen(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts, nil
	}
	if d, err := detector.ParseDuration(strings.TrimSpace(strings.TrimSuffix(s, "ago"))); err == nil && d >= 0 {
		return t.now().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("can't read %q as a time: use RFC 3339 or a duration ago like 15m", s)
}

func bytesStr(n int64) string {
	if n < 0 {
		n = 0
	}
	return detector.FormatBytes(uint64(n))
}
