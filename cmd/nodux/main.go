package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/config"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/engine"
	"github.com/skipjust12/nodux/internal/llm"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	docker := dockerclient.New(cfg.Docker.SocketPath)

	var detectors []detector.Detector
	if cfg.Detectors.CrashLoop.Enabled {
		detectors = append(detectors, detector.NewCrashLoopDetector(
			cfg.Detectors.CrashLoop.RestartThreshold,
			cfg.Detectors.CrashLoop.Window(),
		))
	}
	if cfg.Detectors.Unhealthy.Enabled {
		detectors = append(detectors, detector.NewUnhealthyDetector())
	}

	var eventDetectors []detector.EventDetector
	if cfg.Detectors.OOM.Enabled {
		eventDetectors = append(eventDetectors, detector.NewOOMDetector())
	}
	if cfg.Detectors.Exit.Enabled {
		eventDetectors = append(eventDetectors, detector.NewExitDetector(
			cfg.Detectors.Exit.IgnoreExitCodes,
			cfg.Detectors.OOM.Enabled,
		))
	}

	if len(detectors) == 0 && len(eventDetectors) == 0 {
		slog.Warn("no detectors enabled, nodux will poll but never report anything")
	}

	eng := engine.New(docker, engine.Options{
		Detectors:         detectors,
		EventDetectors:    eventDetectors,
		Actions:           []action.Action{action.NewConsole()},
		Classifier:        llm.NewNoopClassifier(),
		PollInterval:      cfg.PollInterval(),
		AlertCooldown:     cfg.AlertCooldown(),
		ExcludeContainers: cfg.ExcludeContainers,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("nodux starting",
		"socket", cfg.Docker.SocketPath,
		"poll_interval", cfg.PollInterval().String(),
		"alert_cooldown", cfg.AlertCooldown().String(),
		"detectors", enabledNames(detectors, eventDetectors),
	)

	eng.Run(ctx)

	slog.Info("nodux stopped")
}

func enabledNames(detectors []detector.Detector, eventDetectors []detector.EventDetector) []string {
	var names []string
	for _, d := range detectors {
		names = append(names, d.Name())
	}
	for _, d := range eventDetectors {
		names = append(names, d.Name())
	}
	return names
}
