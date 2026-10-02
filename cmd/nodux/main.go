package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/skipjust12/nodux/internal/probe"
	"github.com/skipjust12/nodux/internal/redact"
	"github.com/skipjust12/nodux/internal/server"
	"github.com/skipjust12/nodux/internal/silence"
	"github.com/skipjust12/nodux/internal/state"
	"github.com/skipjust12/nodux/internal/tools"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// How often memory use is recorded for the digest's growth section.
const sampleInterval = 5 * time.Minute

func main() {
	if len(os.Args) > 1 {
		if cmd, ok := commands[os.Args[1]]; ok {
			os.Exit(cmd(os.Args[2:]))
		}
	}

	configPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	printDigest := flag.Bool("digest", false, "print the digest of the last period (digest.every) from the alert history and exit")
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

	if err := a.listen(cfg); err != nil {
		slog.Error("failed to set up", "error", err)
		os.Exit(1)
	}
	receivers := make([]string, len(a.receivers))
	for i, r := range a.receivers {
		receivers[i] = r.Name()
	}
	slog.Info("nodux starting",
		"version", version,
		"host", cfg.Hostname,
		"socket", cfg.Docker.SocketPath,
		"poll_interval", cfg.PollInterval().String(),
		"detectors", enabledNames(a.opts),
		"probes", len(cfg.Probes.Targets),
		"state_dir", cfg.StateDir,
		"incidents", cfg.Incidents.Enabled,
		"receivers", receivers,
		"heartbeat", cfg.Heartbeat.Enabled,
		"llm", cfg.LLM.Enabled,
		"digest", cfg.Digest.Enabled,
		"telegram", cfg.ChatOps.Telegram.Enabled,
		"control_socket", a.controlSocket,
		"metrics", cfg.Server.Listen,
	)

	a.run(ctx, cfg)
	slog.Info("nodux stopped")
}

// app is everything main wires together.
type app struct {
	opts   engine.Options
	engine *engine.Engine
	// receivers are drained on shutdown and reported in /metrics.
	receivers []*action.HTTPAction
	history   *history.Store
	llm       *llm.Anthropic
	toolbox   *tools.Toolbox

	// Set by listen: the control socket (status, silences) and the
	// /metrics listener, each nil if off.
	control, metrics net.Listener
	controlSocket    string
}

// build turns the config into a ready-to-run app.
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
		CollectThrottling: d.CPUThrottle.Enabled,
		Silences:          silence.New(),
		DeployGrace:       cfg.Silences.DeployGrace(),
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
	if d.Expected.Enabled {
		// Even with no names configured: containers can ask to be
		// expected with the nodux.expected=true label.
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
	add := func(r *action.HTTPAction, route action.Route) {
		a.receivers = append(a.receivers, r)
		opts.Actions = append(opts.Actions, action.NewRouted(r, route))
	}
	if wh := cfg.Actions.Webhook; wh.Enabled {
		add(action.NewWebhook(action.WebhookConfig{
			URL:     wh.URL,
			Format:  wh.Format,
			Headers: wh.Headers,
			Timeout: wh.Timeout(),
		}), action.Route{SendResolved: true, Digest: true})
	}
	for _, rc := range cfg.Actions.Receivers {
		route := action.Route{Severities: rc.Severities, Detectors: rc.Detectors, SendResolved: rc.Resolved(), Digest: rc.Digests()}
		var r *action.HTTPAction
		switch rc.Type {
		case "webhook":
			r = action.NewWebhook(action.WebhookConfig{Name: rc.Name, URL: rc.URL, Format: rc.Format, Headers: rc.Headers, Timeout: rc.Timeout()})
		case "telegram":
			r = action.NewTelegram(action.TelegramConfig{Name: rc.Name, BotToken: rc.BotToken, ChatID: rc.ChatID, ThreadID: rc.ThreadID, APIURL: rc.APIURL, Timeout: rc.Timeout()})
		case "ntfy":
			if r, err = action.NewNtfy(action.NtfyConfig{Name: rc.Name, URL: rc.URL, Token: rc.Token, Timeout: rc.Timeout()}); err != nil {
				a.close()
				return nil, fmt.Errorf("receiver %s: %w", rc.Name, err)
			}
		}
		add(r, route)
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

// close drops what build opened; for an app that never ran.
func (a *app) close() {
	for _, r := range a.receivers {
		r.Close(context.Background())
	}
	if a.history != nil {
		a.history.Close()
	}
}

// listen opens the control socket and the /metrics listener. A control
// socket that can't be created only costs the CLI, so it's a warning; a
// metrics address that can't be bound is a config error.
func (a *app) listen(cfg *config.Config) error {
	if path := cfg.Server.SocketPath; path != "" {
		ln, err := server.ListenUnix(path)
		if err != nil {
			slog.Warn("control socket disabled: nodux status and nodux silence won't work", "path", path, "error", err)
		} else {
			a.control, a.controlSocket = ln, path
		}
	}
	if addr := cfg.Server.Listen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("server.listen: %w", err)
		}
		a.metrics = ln
	}
	return nil
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

	if a.control != nil || a.metrics != nil {
		src := &server.Source{
			Engine:       a.engine,
			Version:      version,
			Hostname:     cfg.Hostname,
			Started:      time.Now(),
			PollInterval: cfg.PollInterval(),
			Silences:     a.opts.Silences,
		}
		for _, r := range a.receivers {
			src.Receivers = append(src.Receivers, r)
		}
		if a.llm != nil { // not a typed nil in the interface
			src.LLM = a.llm
		}
		serve := func(what string, ln net.Listener, control bool) {
			goRun(func() {
				if err := server.Serve(ctx, ln, server.Handler(src, control)); err != nil {
					slog.Error(what+" server failed", "error", err)
				}
			})
		}
		if a.control != nil {
			serve("control", a.control, true)
		}
		if a.metrics != nil {
			serve("metrics", a.metrics, false)
		}
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

	// Give queued alerts a chance to go out before exiting.
	closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	var closing sync.WaitGroup
	for _, r := range a.receivers {
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
