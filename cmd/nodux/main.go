package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/config"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/engine"
	"github.com/skipjust12/nodux/internal/heartbeat"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("nodux", version)
		return
	}

	var level slog.LevelVar
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: &level})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	level.Set(cfg.SlogLevel())

	opts, webhook, err := buildOptions(cfg)
	if err != nil {
		slog.Error("failed to set up", "error", err)
		os.Exit(1)
	}
	eng := engine.New(dockerclient.New(cfg.Docker.SocketPath), opts)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("nodux starting",
		"version", version,
		"host", cfg.Hostname,
		"socket", cfg.Docker.SocketPath,
		"poll_interval", cfg.PollInterval().String(),
		"detectors", enabledNames(opts),
		"webhook", cfg.Actions.Webhook.Enabled,
		"heartbeat", cfg.Heartbeat.Enabled,
		"llm", cfg.LLM.Enabled,
	)

	var wg sync.WaitGroup
	if hb := cfg.Heartbeat; hb.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			heartbeat.New(hb.URL, hb.Interval(), eng.Healthy).Run(ctx)
		}()
	}

	eng.Run(ctx)
	wg.Wait()

	if webhook != nil {
		// Give queued alerts a chance to go out before exiting.
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := webhook.Close(closeCtx); err != nil {
			slog.Error("webhook shutdown", "error", err)
		}
		cancel()
	}

	slog.Info("nodux stopped")
}

// buildOptions turns the config into engine options. The webhook, if
// enabled, is returned separately so it can be drained on shutdown.
func buildOptions(cfg *config.Config) (engine.Options, *action.WebhookAction, error) {
	d := cfg.Detectors
	opts := engine.Options{
		Hostname:          cfg.Hostname,
		PollInterval:      cfg.PollInterval(),
		AlertCooldown:     cfg.AlertCooldown(),
		DockerDownAfter:   cfg.DockerDownAfter(),
		ExcludeContainers: cfg.ExcludeContainers,
		CollectStats:      d.Memory.Enabled,
	}

	if d.CrashLoop.Enabled {
		// Restarts come from events; polling closes the episode.
		cl := detector.NewCrashLoopDetector(d.CrashLoop.RestartThreshold, d.CrashLoop.Window())
		opts.Detectors = append(opts.Detectors, cl)
		opts.EventDetectors = append(opts.EventDetectors, cl)
	}
	if d.Unhealthy.Enabled {
		opts.Detectors = append(opts.Detectors, detector.NewUnhealthyDetector())
	}
	if d.Memory.Enabled {
		opts.Detectors = append(opts.Detectors, detector.NewMemoryDetector(d.Memory.ThresholdPercent, d.Memory.For()))
	}
	if d.OOM.Enabled {
		opts.EventDetectors = append(opts.EventDetectors, detector.NewOOMDetector())
	}
	if d.Exit.Enabled {
		opts.EventDetectors = append(opts.EventDetectors, detector.NewExitDetector(d.Exit.IgnoreExitCodes, d.OOM.Enabled))
	}
	if d.Expected.Enabled && len(d.Expected.Containers) > 0 {
		opts.Expected = detector.NewExpectedDetector(d.Expected.Containers, d.Expected.Grace())
	}

	h := cfg.Host
	if h.Disk.Enabled {
		opts.HostDetectors = append(opts.HostDetectors, detector.NewDiskDetector(h.Disk.Paths, h.Disk.ThresholdPercent))
	}
	if h.Memory.Enabled {
		opts.HostDetectors = append(opts.HostDetectors, detector.NewHostMemoryDetector(h.ProcPath, h.Memory.ThresholdPercent, h.Memory.For()))
	}
	if h.CPU.Enabled {
		opts.HostDetectors = append(opts.HostDetectors, detector.NewCPUDetector(h.ProcPath, h.CPU.ThresholdPercent, h.CPU.For()))
	}

	red, err := redact.New(cfg.Redact.Patterns, cfg.Redact.Defaults)
	if err != nil {
		return engine.Options{}, nil, err
	}
	opts.Redactor = red

	opts.Actions = []action.Action{action.NewConsole()}
	var webhook *action.WebhookAction
	if wh := cfg.Actions.Webhook; wh.Enabled {
		webhook = action.NewWebhook(action.WebhookConfig{
			URL:     wh.URL,
			Format:  wh.Format,
			Headers: wh.Headers,
			Timeout: wh.Timeout(),
		})
		opts.Actions = append(opts.Actions, webhook)
	}

	if l := cfg.LLM; l.Enabled {
		opts.Classifier = llm.NewAnthropic(llm.AnthropicConfig{
			APIKey:     l.APIKey,
			Model:      l.Model,
			BaseURL:    l.BaseURL,
			Timeout:    l.Timeout(),
			MaxPerHour: l.MaxPerHour,
		})
	}

	return opts, webhook, nil
}

func enabledNames(opts engine.Options) []string {
	var names []string
	seen := make(map[string]bool)
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, d := range opts.Detectors {
		add(d.Name())
	}
	for _, d := range opts.EventDetectors {
		add(d.Name())
	}
	if opts.Expected != nil {
		add(opts.Expected.Name())
	}
	for _, d := range opts.HostDetectors {
		add(d.Name())
	}
	if opts.DockerDownAfter > 0 {
		add("docker")
	}
	return names
}
