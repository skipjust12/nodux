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
	if len(detectors) == 0 {
		slog.Warn("no detectors enabled, nodux will poll but never report anything")
	}

	actions := []action.Action{action.NewConsole()}
	classifier := llm.NewNoopClassifier()

	eng := engine.New(docker, detectors, actions, classifier, cfg.PollInterval(), cfg.ExcludeContainers)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("nodux starting",
		"socket", cfg.Docker.SocketPath,
		"poll_interval", cfg.PollInterval().String(),
		"crashloop_enabled", cfg.Detectors.CrashLoop.Enabled,
	)

	eng.Run(ctx)

	slog.Info("nodux stopped")
}
