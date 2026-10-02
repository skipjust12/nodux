package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/skipjust12/nodux/internal/digest"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
)

// Config describes the contents of config.yaml. Every field has a
// default (see Default); the file only needs what differs from it.
type Config struct {
	// Hostname is stamped on every alert, so alerts from several
	// servers in one channel can be told apart. Empty = os.Hostname().
	Hostname            string `yaml:"hostname"`
	LogLevel            string `yaml:"log_level"`
	PollIntervalSeconds int    `yaml:"poll_interval_seconds"`
	// AlertCooldownMinutes suppresses repeats of one-off alerts (exit,
	// oom) from the same detector for the same container name. 0
	// disables the cooldown.
	AlertCooldownMinutes int `yaml:"alert_cooldown_minutes"`
	// StateDir keeps open alerts, detector state, silences and the event
	// stream position (state.json) and the alert history (history.db)
	// across restarts. Empty keeps everything in memory.
	StateDir          string          `yaml:"state_dir"`
	History           HistoryConfig   `yaml:"history"`
	Docker            DockerConfig    `yaml:"docker"`
	ExcludeContainers []string        `yaml:"exclude_containers"`
	Detectors         DetectorsConfig `yaml:"detectors"`
	Host              HostConfig      `yaml:"host"`
	Probes            ProbesConfig    `yaml:"probes"`
	Incidents         IncidentsConfig `yaml:"incidents"`
	Redact            RedactConfig    `yaml:"redact"`
	Actions           ActionsConfig   `yaml:"actions"`
	Silences          SilencesConfig  `yaml:"silences"`
	Server            ServerConfig    `yaml:"server"`
	Heartbeat         HeartbeatConfig `yaml:"heartbeat"`
	LLM               LLMConfig       `yaml:"llm"`
	Digest            DigestConfig    `yaml:"digest"`
	ChatOps           ChatOpsConfig   `yaml:"chatops"`
}

type HistoryConfig struct {
	// RetentionDays is how long alerts and LLM usage are kept.
	RetentionDays int `yaml:"retention_days"`
}

// IncidentsConfig groups related alerts into one message.
type IncidentsConfig struct {
	Enabled bool `yaml:"enabled"`
	// GroupWaitSeconds is how long alerts are held to collect related
	// ones before they go out.
	GroupWaitSeconds int `yaml:"group_wait_seconds"`
	// WindowMinutes: an incident takes related alerts while its last
	// one is this recent.
	WindowMinutes int `yaml:"window_minutes"`
}

type DigestConfig struct {
	Enabled bool   `yaml:"enabled"`
	Every   string `yaml:"every"`   // daily or weekly
	At      string `yaml:"at"`      // local time, "09:00"
	Weekday string `yaml:"weekday"` // for weekly
}

type ChatOpsConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	// AllowedChatIDs are the chats the bot answers; everyone else is
	// ignored.
	AllowedChatIDs []int64 `yaml:"allowed_chat_ids"`
}

type DockerConfig struct {
	SocketPath string `yaml:"socket_path"`
	// DownAlertAfterSeconds: alert when the daemon has been unreachable
	// this long. 0 disables the alert.
	DownAlertAfterSeconds int `yaml:"down_alert_after_seconds"`
}

type DetectorsConfig struct {
	CrashLoop CrashLoopConfig `yaml:"crashloop"`
	OOM       ToggleConfig    `yaml:"oom"`
	Unhealthy ToggleConfig    `yaml:"unhealthy"`
	Exit      ExitConfig      `yaml:"exit"`
	Memory    MemoryConfig    `yaml:"memory"`
	Expected  ExpectedConfig  `yaml:"expected"`
	// CPUThrottle: the share of CFS periods a CPU-limited container was
	// throttled in.
	CPUThrottle ThresholdConfig `yaml:"cpu_throttle"`
}

// ToggleConfig is for detectors that have nothing to tune.
type ToggleConfig struct {
	Enabled bool `yaml:"enabled"`
}

type CrashLoopConfig struct {
	Enabled          bool `yaml:"enabled"`
	RestartThreshold int  `yaml:"restart_threshold"`
	WindowMinutes    int  `yaml:"window_minutes"`
}

type ExitConfig struct {
	Enabled bool `yaml:"enabled"`
	// Exit codes that are never reported.
	IgnoreExitCodes []int `yaml:"ignore_exit_codes"`
}

type MemoryConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	// ForSeconds is how long usage must stay above the threshold; 0
	// alerts on the first sample.
	ForSeconds int `yaml:"for_seconds"`
}

type ExpectedConfig struct {
	Enabled bool `yaml:"enabled"`
	// Containers (by name) that must always be running.
	Containers   []string `yaml:"containers"`
	GraceSeconds int      `yaml:"grace_seconds"`
}

type HostConfig struct {
	// ProcPath is where the host's /proc is visible. Inside a container
	// /proc/stat and /proc/meminfo already describe the host.
	ProcPath string          `yaml:"proc_path"`
	Disk     DiskConfig      `yaml:"disk"`
	Memory   ThresholdConfig `yaml:"memory"`
	CPU      ThresholdConfig `yaml:"cpu"`
	Pressure PressureConfig  `yaml:"pressure"`
	OOM      ToggleConfig    `yaml:"oom"`
}

type DiskConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Paths            []string `yaml:"paths"`
	ThresholdPercent float64  `yaml:"threshold_percent"`
	// Forecast predicts when each path will be full; it uses the same
	// paths and runs even if the static threshold is off.
	Forecast DiskForecastConfig `yaml:"forecast"`
}

type DiskForecastConfig struct {
	Enabled bool `yaml:"enabled"`
	// WindowMinutes of samples the fill rate is computed over.
	WindowMinutes int `yaml:"window_minutes"`
	// HorizonHours: alert when the disk is projected to be full sooner.
	HorizonHours int `yaml:"horizon_hours"`
}

// PressureConfig sets avg60 thresholds (percent of wall time stalled)
// for /proc/pressure; 0 turns a signal off.
type PressureConfig struct {
	Enabled    bool    `yaml:"enabled"`
	MemorySome float64 `yaml:"memory_some_percent"`
	MemoryFull float64 `yaml:"memory_full_percent"`
	IOSome     float64 `yaml:"io_some_percent"`
	IOFull     float64 `yaml:"io_full_percent"`
	CPUSome    float64 `yaml:"cpu_some_percent"`
	ForSeconds int     `yaml:"for_seconds"`
}

type ProbesConfig struct {
	IntervalSeconds int `yaml:"interval_seconds"`
	TimeoutSeconds  int `yaml:"timeout_seconds"`
	// Failures in a row before a probe alerts.
	Failures int `yaml:"failures"`
	// CertWarnDays / CertCriticalDays: alert when a certificate seen by
	// an https or tls probe expires within this many days. 0 disables.
	CertWarnDays     int           `yaml:"cert_warn_days"`
	CertCriticalDays int           `yaml:"cert_critical_days"`
	Targets          []ProbeTarget `yaml:"targets"`
}

type ProbeTarget struct {
	Name string `yaml:"name"`
	// Exactly one of URL (http/https GET), TCP (host:port connect) and
	// TLS (host:port handshake).
	URL string `yaml:"url"`
	TCP string `yaml:"tcp"`
	TLS string `yaml:"tls"`
	// Container ties the probe to a container: alerts carry its state
	// and logs.
	Container string `yaml:"container"`
	// Status lists accepted HTTP statuses; empty = 200-399.
	Status     []int `yaml:"status"`
	SkipVerify bool  `yaml:"tls_skip_verify"`
}

type ThresholdConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	ForSeconds       int     `yaml:"for_seconds"`
}

type RedactConfig struct {
	// Defaults enables the built-in patterns (password=..., bearer
	// tokens, credentials in URLs, well-known key formats).
	Defaults bool `yaml:"defaults"`
	// Extra regular expressions; a group named "secret" limits the mask
	// to that group.
	Patterns []string `yaml:"patterns"`
}

type ActionsConfig struct {
	// Webhook is a single receiver that gets everything; kept for
	// configs written before receivers existed.
	Webhook   WebhookConfig    `yaml:"webhook"`
	Receivers []ReceiverConfig `yaml:"receivers"`
}

// ReceiverConfig is one place alerts go, and which alerts go there.
type ReceiverConfig struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // webhook, telegram or ntfy

	// Routing. Empty severities/detectors = all; detectors are globs.
	Severities   []string `yaml:"severities"`
	Detectors    []string `yaml:"detectors"`
	SendResolved *bool    `yaml:"send_resolved"` // default true
	Digest       *bool    `yaml:"digest"`        // the periodic digest; default true

	// webhook and ntfy
	URL            string `yaml:"url"`
	TimeoutSeconds int    `yaml:"timeout_seconds"` // default 5
	// webhook
	Format  string            `yaml:"format"`
	Headers map[string]string `yaml:"headers"`
	// telegram
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
	ThreadID int    `yaml:"thread_id"`
	APIURL   string `yaml:"api_url"`
	// ntfy
	Token string `yaml:"token"`
}

type SilencesConfig struct {
	// DeployGraceSeconds: create, stop and remove events for a container
	// mute its alerts, and those of its compose project, until this long
	// after the last one. 0 disables it.
	DeployGraceSeconds int `yaml:"deploy_grace_seconds"`
}

type ServerConfig struct {
	// SocketPath is the control socket for nodux status / silence. Empty
	// disables it.
	SocketPath string `yaml:"socket_path"`
	// Listen is a TCP address for /metrics and /healthz, e.g.
	// 127.0.0.1:9321. Empty disables it.
	Listen string `yaml:"listen"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Format  string `yaml:"format"` // json or slack
	// Values may reference environment variables ($VAR / ${VAR}), so
	// tokens don't have to live in the config file.
	Headers        map[string]string `yaml:"headers"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
}

type HeartbeatConfig struct {
	Enabled         bool   `yaml:"enabled"`
	URL             string `yaml:"url"`
	IntervalSeconds int    `yaml:"interval_seconds"`
}

// LLMConfig configures the optional LLM layer that adds a probable-cause
// analysis to alerts, answers chat questions and writes the digest's
// takeaway. Everything it reads is redacted first.
type LLMConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
	BaseURL string `yaml:"base_url"`
	Effort  string `yaml:"effort"`
	// MaxSteps is how many rounds of read-only tool calls one analysis
	// may make. 0 = no tools, one request per analysis.
	MaxSteps int `yaml:"max_steps"`
	// TimeoutSeconds bounds a whole analysis, tool calls included.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// MaxPerHour caps analyses, answers and digest notes; alerts over
	// the cap go out without an analysis. 0 = no cap.
	MaxPerHour int `yaml:"max_per_hour"`
}

func (c *Config) PollInterval() time.Duration {
	return seconds(c.PollIntervalSeconds)
}

func (c *Config) AlertCooldown() time.Duration {
	return time.Duration(c.AlertCooldownMinutes) * time.Minute
}

func (c *Config) DockerDownAfter() time.Duration {
	return seconds(c.Docker.DownAlertAfterSeconds)
}

// SlogLevel is the parsed log_level.
func (c *Config) SlogLevel() slog.Level {
	var l slog.Level
	l.UnmarshalText([]byte(c.LogLevel)) // validated in Load
	return l
}

func (c *CrashLoopConfig) Window() time.Duration {
	return time.Duration(c.WindowMinutes) * time.Minute
}

func (c *MemoryConfig) For() time.Duration      { return seconds(c.ForSeconds) }
func (c *PressureConfig) For() time.Duration    { return seconds(c.ForSeconds) }
func (c *ProbesConfig) Interval() time.Duration { return seconds(c.IntervalSeconds) }
func (c *ProbesConfig) Timeout() time.Duration  { return seconds(c.TimeoutSeconds) }
func (c *SilencesConfig) DeployGrace() time.Duration {
	return seconds(c.DeployGraceSeconds)
}
func (c *DiskForecastConfig) Window() time.Duration {
	return time.Duration(c.WindowMinutes) * time.Minute
}
func (c *DiskForecastConfig) Horizon() time.Duration {
	return time.Duration(c.HorizonHours) * time.Hour
}

// Timeout is the receiver's timeout, 5s unless set.
func (r *ReceiverConfig) Timeout() time.Duration {
	if r.TimeoutSeconds == 0 {
		return 5 * time.Second
	}
	return seconds(r.TimeoutSeconds)
}

// Resolved says whether the receiver gets resolutions (default yes).
func (r *ReceiverConfig) Resolved() bool { return r.SendResolved == nil || *r.SendResolved }

// Digests says whether the receiver gets the digest (default yes).
func (r *ReceiverConfig) Digests() bool         { return r.Digest == nil || *r.Digest }
func (c *ExpectedConfig) Grace() time.Duration  { return seconds(c.GraceSeconds) }
func (c *ThresholdConfig) For() time.Duration   { return seconds(c.ForSeconds) }
func (c *WebhookConfig) Timeout() time.Duration { return seconds(c.TimeoutSeconds) }
func (c *HeartbeatConfig) Interval() time.Duration {
	return seconds(c.IntervalSeconds)
}
func (c *LLMConfig) Timeout() time.Duration { return seconds(c.TimeoutSeconds) }
func (c *HistoryConfig) Retention() time.Duration {
	return time.Duration(c.RetentionDays) * 24 * time.Hour
}
func (c *IncidentsConfig) GroupWait() time.Duration { return seconds(c.GroupWaitSeconds) }
func (c *IncidentsConfig) Window() time.Duration {
	return time.Duration(c.WindowMinutes) * time.Minute
}

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }

// Default is the configuration an empty file gives you: every detector
// on, no external notifications.
func Default() *Config {
	return &Config{
		LogLevel:             "info",
		PollIntervalSeconds:  15,
		AlertCooldownMinutes: 10,
		StateDir:             "/var/lib/nodux",
		History:              HistoryConfig{RetentionDays: 30},
		Incidents:            IncidentsConfig{Enabled: true, GroupWaitSeconds: 30, WindowMinutes: 10},
		Docker: DockerConfig{
			SocketPath:            "/var/run/docker.sock",
			DownAlertAfterSeconds: 60,
		},
		Detectors: DetectorsConfig{
			CrashLoop:   CrashLoopConfig{Enabled: true, RestartThreshold: 3, WindowMinutes: 5},
			OOM:         ToggleConfig{Enabled: true},
			Unhealthy:   ToggleConfig{Enabled: true},
			Exit:        ExitConfig{Enabled: true, IgnoreExitCodes: []int{0}},
			Memory:      MemoryConfig{Enabled: true, ThresholdPercent: 90, ForSeconds: 60},
			Expected:    ExpectedConfig{Enabled: true, GraceSeconds: 60},
			CPUThrottle: ThresholdConfig{Enabled: true, ThresholdPercent: 25, ForSeconds: 300},
		},
		Host: HostConfig{
			ProcPath: "/proc",
			Disk: DiskConfig{
				Enabled: true, Paths: []string{"/"}, ThresholdPercent: 90,
				Forecast: DiskForecastConfig{Enabled: true, WindowMinutes: 60, HorizonHours: 12},
			},
			Memory: ThresholdConfig{Enabled: true, ThresholdPercent: 90, ForSeconds: 300},
			CPU:    ThresholdConfig{Enabled: true, ThresholdPercent: 95, ForSeconds: 600},
			Pressure: PressureConfig{
				Enabled: true, MemorySome: 10, IOFull: 10, ForSeconds: 60,
			},
			OOM: ToggleConfig{Enabled: true},
		},
		Probes: ProbesConfig{
			IntervalSeconds: 30, TimeoutSeconds: 5, Failures: 2,
			CertWarnDays: 14, CertCriticalDays: 3,
		},
		Redact:   RedactConfig{Defaults: true},
		Silences: SilencesConfig{DeployGraceSeconds: 120},
		Server:   ServerConfig{SocketPath: "/run/nodux/nodux.sock"},
		Actions: ActionsConfig{Webhook: WebhookConfig{
			Format:         "json",
			TimeoutSeconds: 5,
		}},
		Heartbeat: HeartbeatConfig{IntervalSeconds: 60},
		LLM: LLMConfig{
			APIKey:         "${ANTHROPIC_API_KEY}",
			Model:          llm.DefaultModel,
			Effort:         llm.DefaultEffort,
			MaxSteps:       llm.DefaultMaxSteps,
			TimeoutSeconds: 90,
			MaxPerHour:     30,
		},
		Digest: DigestConfig{Every: "daily", At: "09:00", Weekday: "monday"},
		ChatOps: ChatOpsConfig{Telegram: TelegramConfig{
			Token: "${NODUX_TELEGRAM_TOKEN}",
		}},
	}
}

// Load reads the config file on top of the defaults, expands
// environment variables and validates the result. Unknown keys are an
// error, so a typo doesn't silently fall back to a default.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if err := cfg.expandEnv(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg, nil
}

// expandEnv substitutes $VAR / ${VAR} in the fields that hold secrets,
// for the features that are enabled. A variable that's unset or empty
// is an error: silently substituting "" turns
// https://hooks.slack.com/services/${NODUX_SLACK_PATH} into a URL that
// validates fine and 404s on every alert.
func (c *Config) expandEnv() error {
	var missing []string
	expand := func(field, s string) string {
		return os.Expand(s, func(name string) string {
			v, ok := os.LookupEnv(name)
			if !ok || v == "" {
				missing = append(missing, fmt.Sprintf("$%s (in %s)", name, field))
			}
			return v
		})
	}

	if wh := &c.Actions.Webhook; wh.Enabled {
		wh.URL = expand("actions.webhook.url", wh.URL)
		for k, v := range wh.Headers {
			wh.Headers[k] = expand("actions.webhook.headers."+k, v)
		}
	}
	for i := range c.Actions.Receivers {
		r := &c.Actions.Receivers[i]
		field := fmt.Sprintf("actions.receivers[%d]", i)
		if r.Name != "" {
			field = "actions.receivers." + r.Name
		}
		r.URL = expand(field+".url", r.URL)
		r.APIURL = expand(field+".api_url", r.APIURL)
		r.BotToken = expand(field+".bot_token", r.BotToken)
		r.ChatID = expand(field+".chat_id", r.ChatID)
		r.Token = expand(field+".token", r.Token)
		for k, v := range r.Headers {
			r.Headers[k] = expand(field+".headers."+k, v)
		}
	}
	for i := range c.Probes.Targets {
		t := &c.Probes.Targets[i]
		t.URL = expand("probes.targets."+t.Name+".url", t.URL)
	}
	if hb := &c.Heartbeat; hb.Enabled {
		hb.URL = expand("heartbeat.url", hb.URL)
	}
	if l := &c.LLM; l.Enabled {
		l.APIKey = expand("llm.api_key", l.APIKey)
		l.BaseURL = expand("llm.base_url", l.BaseURL)
	}
	if tg := &c.ChatOps.Telegram; tg.Enabled {
		tg.Token = expand("chatops.telegram.token", tg.Token)
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("environment variables not set: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *Config) validate() error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("log_level must be debug, info, warn or error, got %q", c.LogLevel)
	}
	if c.PollIntervalSeconds <= 0 {
		return fmt.Errorf("poll_interval_seconds must be positive")
	}
	if c.AlertCooldownMinutes < 0 {
		return fmt.Errorf("alert_cooldown_minutes must not be negative")
	}
	if c.StateDir != "" && !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("state_dir must be an absolute path, got %q", c.StateDir)
	}
	if c.StateDir != "" && c.History.RetentionDays <= 0 {
		return fmt.Errorf("history.retention_days must be positive")
	}
	if c.Docker.SocketPath == "" {
		return fmt.Errorf("docker.socket_path must not be empty")
	}
	if c.Docker.DownAlertAfterSeconds < 0 {
		return fmt.Errorf("docker.down_alert_after_seconds must not be negative")
	}

	d := c.Detectors
	if d.CrashLoop.Enabled {
		if d.CrashLoop.RestartThreshold <= 0 {
			return fmt.Errorf("detectors.crashloop.restart_threshold must be positive")
		}
		if d.CrashLoop.WindowMinutes <= 0 {
			return fmt.Errorf("detectors.crashloop.window_minutes must be positive")
		}
	}
	if d.Memory.Enabled {
		if err := checkThreshold("detectors.memory", d.Memory.ThresholdPercent, d.Memory.ForSeconds); err != nil {
			return err
		}
	}
	if d.Expected.Enabled && d.Expected.GraceSeconds < 0 {
		return fmt.Errorf("detectors.expected.grace_seconds must not be negative")
	}
	if d.CPUThrottle.Enabled {
		if err := checkThreshold("detectors.cpu_throttle", d.CPUThrottle.ThresholdPercent, d.CPUThrottle.ForSeconds); err != nil {
			return err
		}
	}

	h := c.Host
	if (h.Disk.Enabled || h.Disk.Forecast.Enabled) && len(h.Disk.Paths) == 0 {
		return fmt.Errorf("host.disk.paths must list at least one path")
	}
	if h.Disk.Enabled {
		if err := checkThreshold("host.disk", h.Disk.ThresholdPercent, 0); err != nil {
			return err
		}
	}
	if f := h.Disk.Forecast; f.Enabled {
		if f.WindowMinutes <= 0 {
			return fmt.Errorf("host.disk.forecast.window_minutes must be positive")
		}
		if f.HorizonHours <= 0 {
			return fmt.Errorf("host.disk.forecast.horizon_hours must be positive")
		}
	}
	if p := h.Pressure; p.Enabled {
		for name, v := range map[string]float64{
			"memory_some_percent": p.MemorySome, "memory_full_percent": p.MemoryFull,
			"io_some_percent": p.IOSome, "io_full_percent": p.IOFull, "cpu_some_percent": p.CPUSome,
		} {
			if v < 0 || v > 100 {
				return fmt.Errorf("host.pressure.%s must be in [0, 100]", name)
			}
		}
		if p.ForSeconds < 0 {
			return fmt.Errorf("host.pressure.for_seconds must not be negative")
		}
	}
	if h.Memory.Enabled {
		if err := checkThreshold("host.memory", h.Memory.ThresholdPercent, h.Memory.ForSeconds); err != nil {
			return err
		}
	}
	if h.CPU.Enabled {
		if err := checkThreshold("host.cpu", h.CPU.ThresholdPercent, h.CPU.ForSeconds); err != nil {
			return err
		}
	}
	if (h.Memory.Enabled || h.CPU.Enabled || h.Pressure.Enabled || h.OOM.Enabled) && h.ProcPath == "" {
		return fmt.Errorf("host.proc_path must not be empty")
	}

	if in := c.Incidents; in.Enabled {
		if in.GroupWaitSeconds < 0 {
			return fmt.Errorf("incidents.group_wait_seconds must not be negative")
		}
		if in.WindowMinutes <= 0 {
			return fmt.Errorf("incidents.window_minutes must be positive")
		}
	}

	for _, p := range c.Redact.Patterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("redact.patterns: %q: %w", p, err)
		}
	}

	if err := c.Probes.validate(); err != nil {
		return err
	}

	if wh := c.Actions.Webhook; wh.Enabled {
		if err := checkURL("actions.webhook.url", wh.URL); err != nil {
			return err
		}
		if wh.Format != "json" && wh.Format != "slack" {
			return fmt.Errorf("actions.webhook.format must be json or slack, got %q", wh.Format)
		}
		if wh.TimeoutSeconds <= 0 {
			return fmt.Errorf("actions.webhook.timeout_seconds must be positive")
		}
	}
	names := map[string]bool{}
	if c.Actions.Webhook.Enabled {
		names["webhook"] = true
	}
	for i, r := range c.Actions.Receivers {
		if err := r.validate(); err != nil {
			return fmt.Errorf("actions.receivers[%d]: %w", i, err)
		}
		if names[r.Name] {
			return fmt.Errorf("actions.receivers[%d]: duplicate name %q", i, r.Name)
		}
		names[r.Name] = true
	}
	if c.Silences.DeployGraceSeconds < 0 {
		return fmt.Errorf("silences.deploy_grace_seconds must not be negative")
	}
	if l := c.Server.Listen; l != "" {
		if _, _, err := net.SplitHostPort(l); err != nil {
			return fmt.Errorf("server.listen must be host:port, got %q", l)
		}
	}
	if hb := c.Heartbeat; hb.Enabled {
		if err := checkURL("heartbeat.url", hb.URL); err != nil {
			return err
		}
		if hb.IntervalSeconds <= 0 {
			return fmt.Errorf("heartbeat.interval_seconds must be positive")
		}
	}
	if l := c.LLM; l.Enabled {
		if l.APIKey == "" {
			return fmt.Errorf("llm.api_key must be set when the LLM layer is enabled")
		}
		if l.Model == "" {
			return fmt.Errorf("llm.model must not be empty")
		}
		if l.BaseURL != "" {
			if err := checkURL("llm.base_url", l.BaseURL); err != nil {
				return err
			}
		}
		if l.TimeoutSeconds <= 0 {
			return fmt.Errorf("llm.timeout_seconds must be positive")
		}
		if l.MaxPerHour < 0 {
			return fmt.Errorf("llm.max_per_hour must not be negative")
		}
		switch l.Effort {
		case "low", "medium", "high", "xhigh", "max":
		default:
			return fmt.Errorf("llm.effort must be low, medium, high, xhigh or max, got %q", l.Effort)
		}
		if l.MaxSteps < 0 || l.MaxSteps > 10 {
			return fmt.Errorf("llm.max_steps must be between 0 and 10")
		}
	}

	if d := c.Digest; d.Enabled {
		if c.StateDir == "" {
			return fmt.Errorf("digest needs state_dir: it's built from the alert history")
		}
		if _, err := digest.ParseSchedule(d.Every, d.At, d.Weekday); err != nil {
			return fmt.Errorf("digest: %w", err)
		}
	}
	if tg := c.ChatOps.Telegram; tg.Enabled && tg.Token == "" {
		return fmt.Errorf("chatops.telegram.token must be set when the bot is enabled")
	}
	return nil
}

func (p *ProbesConfig) validate() error {
	if len(p.Targets) == 0 {
		return nil
	}
	if p.IntervalSeconds <= 0 {
		return fmt.Errorf("probes.interval_seconds must be positive")
	}
	if p.TimeoutSeconds <= 0 {
		return fmt.Errorf("probes.timeout_seconds must be positive")
	}
	if p.Failures <= 0 {
		return fmt.Errorf("probes.failures must be positive")
	}
	if p.CertWarnDays < 0 || p.CertCriticalDays < 0 {
		return fmt.Errorf("probes.cert_warn_days and cert_critical_days must not be negative")
	}
	if p.CertWarnDays > 0 && p.CertCriticalDays > p.CertWarnDays {
		return fmt.Errorf("probes.cert_critical_days must not be more than cert_warn_days")
	}
	seen := map[string]bool{}
	for i, t := range p.Targets {
		field := fmt.Sprintf("probes.targets[%d]", i)
		if t.Name == "" {
			return fmt.Errorf("%s: name must be set", field)
		}
		if seen[t.Name] {
			return fmt.Errorf("%s: duplicate name %q", field, t.Name)
		}
		seen[t.Name] = true
		field = "probes.targets." + t.Name

		set := 0
		for _, v := range []string{t.URL, t.TCP, t.TLS} {
			if v != "" {
				set++
			}
		}
		if set != 1 {
			return fmt.Errorf("%s: set exactly one of url, tcp and tls", field)
		}
		switch {
		case t.URL != "":
			if err := checkURL(field+".url", t.URL); err != nil {
				return err
			}
		case t.TCP != "":
			if _, _, err := net.SplitHostPort(t.TCP); err != nil {
				return fmt.Errorf("%s.tcp must be host:port, got %q", field, t.TCP)
			}
		default:
			if _, _, err := net.SplitHostPort(t.TLS); err != nil {
				return fmt.Errorf("%s.tls must be host:port, got %q", field, t.TLS)
			}
		}
		if len(t.Status) > 0 && t.URL == "" {
			return fmt.Errorf("%s: status only applies to url probes", field)
		}
		for _, code := range t.Status {
			if code < 100 || code > 599 {
				return fmt.Errorf("%s.status: %d is not an HTTP status", field, code)
			}
		}
		if t.SkipVerify && t.TCP != "" {
			return fmt.Errorf("%s: tls_skip_verify doesn't apply to tcp probes", field)
		}
	}
	return nil
}

func (r *ReceiverConfig) validate() error {
	if r.Name == "" {
		return fmt.Errorf("name must be set")
	}
	for _, s := range r.Severities {
		if s != "warning" && s != "critical" {
			return fmt.Errorf("%s: severities must be warning or critical, got %q", r.Name, s)
		}
	}
	for _, d := range r.Detectors {
		if _, err := path.Match(d, ""); err != nil {
			return fmt.Errorf("%s: bad detector pattern %q", r.Name, d)
		}
	}
	if r.TimeoutSeconds < 0 {
		return fmt.Errorf("%s: timeout_seconds must not be negative", r.Name)
	}

	// Fields that belong to another type are almost certainly a mistake.
	foreign := map[string]bool{
		"url":       r.URL != "",
		"format":    r.Format != "",
		"headers":   len(r.Headers) > 0,
		"bot_token": r.BotToken != "",
		"chat_id":   r.ChatID != "",
		"thread_id": r.ThreadID != 0,
		"api_url":   r.APIURL != "",
		"token":     r.Token != "",
	}
	var allowed []string
	switch r.Type {
	case "webhook":
		allowed = []string{"url", "format", "headers"}
		if err := checkURL("actions.receivers."+r.Name+".url", r.URL); err != nil {
			return err
		}
		if r.Format != "" && r.Format != "json" && r.Format != "slack" {
			return fmt.Errorf("%s: format must be json or slack, got %q", r.Name, r.Format)
		}
	case "telegram":
		allowed = []string{"bot_token", "chat_id", "thread_id", "api_url"}
		if r.BotToken == "" || r.ChatID == "" {
			return fmt.Errorf("%s: telegram needs bot_token and chat_id", r.Name)
		}
		if r.APIURL != "" {
			if err := checkURL("actions.receivers."+r.Name+".api_url", r.APIURL); err != nil {
				return err
			}
		}
	case "ntfy":
		allowed = []string{"url", "token"}
		if err := checkURL("actions.receivers."+r.Name+".url", r.URL); err != nil {
			return err
		}
		if u, _ := url.Parse(r.URL); strings.Trim(u.Path, "/") == "" {
			return fmt.Errorf("%s: ntfy url must include the topic (https://ntfy.sh/mytopic)", r.Name)
		}
	default:
		return fmt.Errorf("%s: type must be webhook, telegram or ntfy, got %q", r.Name, r.Type)
	}
	for _, a := range allowed {
		delete(foreign, a)
	}
	var bad []string
	for k, set := range foreign {
		if set {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("%s: %s don't apply to type %s", r.Name, strings.Join(bad, ", "), r.Type)
	}
	return nil
}

func checkThreshold(field string, pct float64, forSeconds int) error {
	if pct <= 0 || pct > 100 {
		return fmt.Errorf("%s.threshold_percent must be in (0, 100]", field)
	}
	if forSeconds < 0 {
		return fmt.Errorf("%s.for_seconds must not be negative", field)
	}
	return nil
}

// checkURL validates an http(s) URL without echoing it: these URLs are
// usually credentials.
func checkURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s must be an http(s) URL, got %s", field, redact.URL(raw))
	}
	return nil
}
