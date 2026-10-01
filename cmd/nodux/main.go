package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/skipjust12/nodux/internal/probe"
	"github.com/skipjust12/nodux/internal/redact"
	"github.com/skipjust12/nodux/internal/server"
	"github.com/skipjust12/nodux/internal/silence"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		if cmd, ok := commands[os.Args[1]]; ok {
			os.Exit(cmd(os.Args[2:]))
		}
	}

	configPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", flag.Arg(0))
		usage()
		os.Exit(2)
	}

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

	st, err := build(cfg)
	if err != nil {
		slog.Error("failed to set up", "error", err)
		os.Exit(1)
	}
	eng := engine.New(dockerclient.New(cfg.Docker.SocketPath), st.opts)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src := &server.Source{
		Engine:       eng,
		Version:      version,
		Hostname:     cfg.Hostname,
		Started:      time.Now(),
		PollInterval: cfg.PollInterval(),
		Silences:     st.opts.Silences,
	}
	for _, r := range st.receivers {
		src.Receivers = append(src.Receivers, r)
	}
	if st.llm != nil {
		src.LLM = st.llm
	}

	var wg sync.WaitGroup
	serve := func(what string, ln net.Listener, control bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Serve(ctx, ln, server.Handler(src, control)); err != nil {
				slog.Error(what+" server failed", "error", err)
			}
		}()
	}
	controlSocket := ""
	if path := cfg.Server.SocketPath; path != "" {
		if ln, err := server.ListenUnix(path); err != nil {
			// Not fatal: monitoring matters more than the CLI.
			slog.Warn("control socket disabled: nodux status and nodux silence won't work", "path", path, "error", err)
		} else {
			controlSocket = path
			serve("control", ln, true)
		}
	}
	if addr := cfg.Server.Listen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Error("failed to listen for /metrics", "listen", addr, "error", err)
			os.Exit(1)
		}
		serve("metrics", ln, false)
	}

	names := make([]string, len(st.receivers))
	for i, r := range st.receivers {
		names[i] = r.Name()
	}
	slog.Info("nodux starting",
		"version", version,
		"host", cfg.Hostname,
		"socket", cfg.Docker.SocketPath,
		"poll_interval", cfg.PollInterval().String(),
		"detectors", enabledNames(st.opts),
		"probes", len(cfg.Probes.Targets),
		"receivers", names,
		"heartbeat", cfg.Heartbeat.Enabled,
		"llm", cfg.LLM.Enabled,
		"control_socket", controlSocket,
		"metrics", cfg.Server.Listen,
	)

	if hb := cfg.Heartbeat; hb.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			heartbeat.New(hb.URL, hb.Interval(), eng.Healthy).Run(ctx)
		}()
	}

	eng.Run(ctx)
	wg.Wait()

	// Give queued alerts a chance to go out before exiting.
	closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	var closing sync.WaitGroup
	for _, r := range st.receivers {
		closing.Add(1)
		go func() {
			defer closing.Done()
			if err := r.Close(closeCtx); err != nil {
				slog.Error("receiver shutdown", "receiver", r.Name(), "error", err)
			}
		}()
	}
	closing.Wait()
	cancel()

	slog.Info("nodux stopped")
}

// setup is what the config turns into.
type setup struct {
	opts engine.Options
	// receivers are drained on shutdown and reported in /metrics.
	receivers []*action.HTTPAction
	llm       *llm.Anthropic
}

// build turns the config into engine options and the pieces around
// them.
func build(cfg *config.Config) (*setup, error) {
	d := cfg.Detectors
	st := &setup{}
	opts := engine.Options{
		Hostname:          cfg.Hostname,
		PollInterval:      cfg.PollInterval(),
		AlertCooldown:     cfg.AlertCooldown(),
		DockerDownAfter:   cfg.DockerDownAfter(),
		ExcludeContainers: cfg.ExcludeContainers,
		CollectStats:      d.Memory.Enabled,
		CollectThrottling: d.CPUThrottle.Enabled,
		Silences:          silence.New(),
		DeployGrace:       cfg.Silences.DeployGrace(),
	}

	if d.CrashLoop.Enabled {
		// Restarts come from events; polling closes the episode.
		cl := detector.NewCrashLoopDetector(d.CrashLoop.RestartThreshold, d.CrashLoop.Window())
		opts.Detectors = append(opts.Detectors, cl)
		opts.EventDetectors = append(opts.EventDetectors, cl)
	}
	if d.Unhealthy.Enabled {
		// The health_status event alerts; polling closes the episode.
		u := detector.NewUnhealthyDetector()
		opts.Detectors = append(opts.Detectors, u)
		opts.EventDetectors = append(opts.EventDetectors, u)
	}
	if d.Memory.Enabled {
		opts.Detectors = append(opts.Detectors, detector.NewMemoryDetector(d.Memory.ThresholdPercent, d.Memory.For()))
	}
	if d.CPUThrottle.Enabled {
		opts.Detectors = append(opts.Detectors, detector.NewThrottleDetector(d.CPUThrottle.ThresholdPercent, d.CPUThrottle.For()))
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
	if f := h.Disk.Forecast; f.Enabled {
		opts.HostDetectors = append(opts.HostDetectors, detector.NewDiskForecastDetector(h.Disk.Paths, f.Window(), f.Horizon()))
	}
	if h.Memory.Enabled {
		opts.HostDetectors = append(opts.HostDetectors, detector.NewHostMemoryDetector(h.ProcPath, h.Memory.ThresholdPercent, h.Memory.For()))
	}
	if h.CPU.Enabled {
		opts.HostDetectors = append(opts.HostDetectors, detector.NewCPUDetector(h.ProcPath, h.CPU.ThresholdPercent, h.CPU.For()))
	}
	if p := h.Pressure; p.Enabled {
		var rules []detector.PressureRule
		for _, r := range []detector.PressureRule{
			{Resource: "memory", Kind: "some", Threshold: p.MemorySome},
			{Resource: "memory", Kind: "full", Threshold: p.MemoryFull},
			{Resource: "io", Kind: "some", Threshold: p.IOSome},
			{Resource: "io", Kind: "full", Threshold: p.IOFull},
			{Resource: "cpu", Kind: "some", Threshold: p.CPUSome},
		} {
			if r.Threshold > 0 {
				rules = append(rules, r)
			}
		}
		if len(rules) > 0 {
			opts.HostDetectors = append(opts.HostDetectors, detector.NewPressureDetector(h.ProcPath, rules, p.For()))
		}
	}
	if h.OOM.Enabled {
		// Long enough for a container's oom event to arrive on either
		// side of the poll that sees the counter move.
		settle := max(2*cfg.PollInterval(), 30*time.Second)
		opts.HostOOM = detector.NewHostOOMDetector(h.ProcPath, settle, cfg.AlertCooldown())
	}

	if p := cfg.Probes; len(p.Targets) > 0 {
		targets := make([]probe.Target, len(p.Targets))
		for i, t := range p.Targets {
			targets[i] = probe.Target{
				Name: t.Name, URL: t.URL, TCP: t.TCP, TLS: t.TLS,
				Container: t.Container, Status: t.Status, SkipVerify: t.SkipVerify,
			}
		}
		prober := probe.New(probe.Config{Targets: targets, Timeout: p.Timeout(), Failures: p.Failures})
		opts.Probes = append(opts.Probes, prober)
		if p.CertWarnDays > 0 {
			day := 24 * time.Hour
			opts.Probes = append(opts.Probes, probe.NewCertDetector(prober, time.Duration(p.CertWarnDays)*day, time.Duration(p.CertCriticalDays)*day))
		}
		opts.ProbeInterval = p.Interval()
	}

	red, err := redact.New(cfg.Redact.Patterns, cfg.Redact.Defaults)
	if err != nil {
		return nil, err
	}
	opts.Redactor = red

	opts.Actions = []action.Action{action.NewConsole()}
	add := func(a *action.HTTPAction, r action.Route) {
		st.receivers = append(st.receivers, a)
		opts.Actions = append(opts.Actions, action.NewRouted(a, r))
	}
	if wh := cfg.Actions.Webhook; wh.Enabled {
		add(action.NewWebhook(action.WebhookConfig{
			URL:     wh.URL,
			Format:  wh.Format,
			Headers: wh.Headers,
			Timeout: wh.Timeout(),
		}), action.Route{SendResolved: true})
	}
	for _, rc := range cfg.Actions.Receivers {
		route := action.Route{Severities: rc.Severities, Detectors: rc.Detectors, SendResolved: rc.Resolved()}
		var a *action.HTTPAction
		switch rc.Type {
		case "webhook":
			a = action.NewWebhook(action.WebhookConfig{Name: rc.Name, URL: rc.URL, Format: rc.Format, Headers: rc.Headers, Timeout: rc.Timeout()})
		case "telegram":
			a = action.NewTelegram(action.TelegramConfig{Name: rc.Name, BotToken: rc.BotToken, ChatID: rc.ChatID, ThreadID: rc.ThreadID, APIURL: rc.APIURL, Timeout: rc.Timeout()})
		case "ntfy":
			if a, err = action.NewNtfy(action.NtfyConfig{Name: rc.Name, URL: rc.URL, Token: rc.Token, Timeout: rc.Timeout()}); err != nil {
				st.close()
				return nil, fmt.Errorf("receiver %s: %w", rc.Name, err)
			}
		}
		add(a, route)
	}

	if l := cfg.LLM; l.Enabled {
		st.llm = llm.NewAnthropic(llm.AnthropicConfig{
			APIKey:     l.APIKey,
			Model:      l.Model,
			BaseURL:    l.BaseURL,
			Timeout:    l.Timeout(),
			MaxPerHour: l.MaxPerHour,
		})
		opts.Classifier = st.llm
	}

	st.opts = opts
	return st, nil
}

// close drops the receivers' queues; for setups that never ran.
func (st *setup) close() {
	for _, r := range st.receivers {
		r.Close(context.Background())
	}
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
	if opts.HostOOM != nil {
		add(opts.HostOOM.Name())
	}
	for _, d := range opts.Probes {
		add(d.Name())
	}
	if opts.DockerDownAfter > 0 {
		add("docker")
	}
	return names
}
