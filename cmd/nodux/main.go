package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // digest times in TZ=..., even in a distroless image

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/chatops"
	"github.com/skipjust12/nodux/internal/config"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/digest"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/engine"
	"github.com/skipjust12/nodux/internal/heartbeat"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/incident"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
	"github.com/skipjust12/nodux/internal/state"
	"github.com/skipjust12/nodux/internal/tools"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// How often memory use is recorded for the digest's growth section.
const sampleInterval = 5 * time.Minute

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	printDigest := flag.Bool("digest", false, "print the digest of the last period (digest.every) from the alert history and exit")
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

	if *printDigest {
		text, err := digestNow(context.Background(), cfg, time.Now())
		if err != nil {
			slog.Error("failed to build the digest", "error", err)
			os.Exit(1)
		}
		fmt.Println(text)
		return
	}

	a, err := build(cfg)
	if err != nil {
		slog.Error("failed to set up", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("nodux starting",
		"version", version,
		"host", cfg.Hostname,
		"socket", cfg.Docker.SocketPath,
		"poll_interval", cfg.PollInterval().String(),
		"detectors", enabledNames(a.opts),
		"state_dir", cfg.StateDir,
		"incidents", cfg.Incidents.Enabled,
		"webhook", cfg.Actions.Webhook.Enabled,
		"heartbeat", cfg.Heartbeat.Enabled,
		"llm", cfg.LLM.Enabled,
		"digest", cfg.Digest.Enabled,
		"telegram", cfg.ChatOps.Telegram.Enabled,
	)

	a.run(ctx, cfg)
	slog.Info("nodux stopped")
}

// app is everything main wires together.
type app struct {
	opts    engine.Options
	engine  *engine.Engine
	webhook *action.WebhookAction
	history *history.Store
	llm     *llm.Anthropic
	toolbox *tools.Toolbox
}

// build turns the config into a ready-to-run app. The webhook, if
// enabled, is kept separately so it can be drained on shutdown.
func build(cfg *config.Config) (*app, error) {
	a := &app{}
	d := cfg.Detectors
	opts := engine.Options{
		Hostname:          cfg.Hostname,
		PollInterval:      cfg.PollInterval(),
		AlertCooldown:     cfg.AlertCooldown(),
		DockerDownAfter:   cfg.DockerDownAfter(),
		ExcludeContainers: cfg.ExcludeContainers,
		CollectStats:      d.Memory.Enabled,
	}
	if in := cfg.Incidents; in.Enabled {
		opts.Grouping = incident.Config{Enabled: true, GroupWait: in.GroupWait(), Window: in.Window()}
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
	if d.Expected.Enabled {
		// Even with no names configured: containers can ask to be
		// expected with the nodux.expected=true label.
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
		return nil, err
	}
	opts.Redactor = red

	if cfg.StateDir != "" {
		st, err := state.Open(cfg.StateDir)
		if err != nil {
			return nil, fmt.Errorf("%w (set state_dir to a writable directory, or to \"\" to keep state in memory)", err)
		}
		hist, err := history.Open(cfg.StateDir)
		if err != nil {
			return nil, err
		}
		opts.State, opts.History, opts.SampleInterval = st, hist, sampleInterval
		a.history = hist
	}

	opts.Actions = []action.Action{action.NewConsole()}
	if wh := cfg.Actions.Webhook; wh.Enabled {
		a.webhook = action.NewWebhook(action.WebhookConfig{
			URL:     wh.URL,
			Format:  wh.Format,
			Headers: wh.Headers,
			Timeout: wh.Timeout(),
		})
		opts.Actions = append(opts.Actions, a.webhook)
	}

	docker := dockerclient.New(cfg.Docker.SocketPath)
	// The toolbox and the engine need each other: the model can ask
	// what's open right now. eng is set before anything runs.
	var eng *engine.Engine
	openAlerts := func() []detector.Issue { return eng.ActiveAlerts() }
	diskPaths := h.Disk.Paths
	if !h.Disk.Enabled {
		diskPaths = nil
	}
	a.toolbox = tools.New(tools.Config{
		Docker:     docker,
		History:    a.history,
		Redactor:   red,
		ProcPath:   h.ProcPath,
		DiskPaths:  diskPaths,
		Exclude:    cfg.ExcludeContainers,
		OpenAlerts: openAlerts,
	})

	if l := cfg.LLM; l.Enabled {
		var onUsage func(llm.Usage)
		if hist := a.history; hist != nil {
			onUsage = func(u llm.Usage) {
				err := hist.AddLLMCall(context.Background(), history.LLMCall{
					Run: u.Run, Purpose: u.Purpose, Model: u.Model,
					Input: u.Input, Output: u.Output, CacheRead: u.CacheRead, CacheWrite: u.CacheWrite,
				})
				if err != nil {
					slog.Warn("recording LLM usage failed", "error", err)
				}
			}
		}
		a.llm = llm.NewAnthropic(llm.AnthropicConfig{
			APIKey:     l.APIKey,
			Model:      l.Model,
			BaseURL:    l.BaseURL,
			Effort:     l.Effort,
			Timeout:    l.Timeout(),
			MaxPerHour: l.MaxPerHour,
			Toolbox:    a.toolbox,
			MaxSteps:   l.MaxSteps,
			Host:       cfg.Hostname,
			OnUsage:    onUsage,
		})
		opts.Analyzer = a.llm
	}

	eng = engine.New(docker, opts)
	a.opts, a.engine = opts, eng
	return a, nil
}

// run starts everything and blocks until ctx is cancelled and every
// part has shut down.
func (a *app) run(ctx context.Context, cfg *config.Config) {
	var wg sync.WaitGroup
	goRun := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	if hb := cfg.Heartbeat; hb.Enabled {
		goRun(func() { heartbeat.New(hb.URL, hb.Interval(), a.engine.Healthy).Run(ctx) })
	}
	if a.history != nil {
		goRun(func() { maintainHistory(ctx, a.history, cfg.History.Retention()) })
	}
	if d := cfg.Digest; d.Enabled {
		sched, _ := digest.ParseSchedule(d.Every, d.At, d.Weekday) // validated in config.Load
		b := &digest.Builder{History: a.history, OpenAlerts: a.engine.ActiveAlerts, Host: cfg.Hostname}
		if a.llm != nil {
			b.Summarizer = a.llm
		}
		goRun(func() { digest.Run(ctx, sched, b, a.opts.Actions) })
	}
	if tg := cfg.ChatOps.Telegram; tg.Enabled {
		botCfg := chatops.Config{
			Token:        tg.Token,
			AllowedChats: tg.AllowedChatIDs,
			Tools:        a.toolbox,
			OpenAlerts:   a.engine.ActiveAlerts,
			Host:         cfg.Hostname,
		}
		if a.llm != nil { // not a typed nil in the interface
			botCfg.Answerer = a.llm
		}
		bot := chatops.New(botCfg)
		goRun(func() { bot.Run(ctx) })
	}

	a.engine.Run(ctx)
	wg.Wait()

	if a.webhook != nil {
		// Give queued alerts a chance to go out before exiting.
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := a.webhook.Close(closeCtx); err != nil {
			slog.Error("webhook shutdown", "error", err)
		}
		cancel()
	}
	if a.history != nil {
		a.history.Close()
	}
}

// digestNow builds the digest that would go out at now, for a look at
// it without waiting for the schedule. Open alerts aren't in it: they
// live in the running daemon.
func digestNow(ctx context.Context, cfg *config.Config, now time.Time) (string, error) {
	if cfg.StateDir == "" {
		return "", errors.New("the digest is built from the alert history: set state_dir")
	}
	sched, err := digest.ParseSchedule(cfg.Digest.Every, cfg.Digest.At, cfg.Digest.Weekday)
	if err != nil {
		return "", fmt.Errorf("digest: %w", err)
	}
	hist, err := history.Open(cfg.StateDir)
	if err != nil {
		return "", err
	}
	defer hist.Close()
	b := &digest.Builder{History: hist, Host: cfg.Hostname}
	if l := cfg.LLM; l.Enabled {
		b.Summarizer = llm.NewAnthropic(llm.AnthropicConfig{
			APIKey: l.APIKey, Model: l.Model, BaseURL: l.BaseURL, Effort: l.Effort, Timeout: l.Timeout(), Host: cfg.Hostname,
		})
	}
	from, to := sched.Period(now)
	d, err := b.Build(ctx, sched.Title(), from, to)
	if err != nil {
		return "", err
	}
	return d.Text, nil
}

// maintainHistory drops old rows at startup and then once a day.
func maintainHistory(ctx context.Context, h *history.Store, retention time.Duration) {
	for {
		if err := h.Prune(ctx, retention); err != nil && ctx.Err() == nil {
			slog.Warn("pruning alert history failed", "error", err)
		}
		t := time.NewTimer(24 * time.Hour)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
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
	if opts.DockerDownAfter > 0 {
		add("docker")
	}
	return names
}
