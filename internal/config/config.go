package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
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
	// StateDir keeps open alerts, detector state and the event stream
	// position (state.json) and the alert history (history.db) across
	// restarts. Empty keeps everything in memory.
	StateDir          string          `yaml:"state_dir"`
	History           HistoryConfig   `yaml:"history"`
	Docker            DockerConfig    `yaml:"docker"`
	ExcludeContainers []string        `yaml:"exclude_containers"`
	Detectors         DetectorsConfig `yaml:"detectors"`
	Host              HostConfig      `yaml:"host"`
	Incidents         IncidentsConfig `yaml:"incidents"`
	Redact            RedactConfig    `yaml:"redact"`
	Actions           ActionsConfig   `yaml:"actions"`
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
}

type DiskConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Paths            []string `yaml:"paths"`
	ThresholdPercent float64  `yaml:"threshold_percent"`
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
	Webhook WebhookConfig `yaml:"webhook"`
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
			CrashLoop: CrashLoopConfig{Enabled: true, RestartThreshold: 3, WindowMinutes: 5},
			OOM:       ToggleConfig{Enabled: true},
			Unhealthy: ToggleConfig{Enabled: true},
			Exit:      ExitConfig{Enabled: true, IgnoreExitCodes: []int{0}},
			Memory:    MemoryConfig{Enabled: true, ThresholdPercent: 90, ForSeconds: 60},
			Expected:  ExpectedConfig{Enabled: true, GraceSeconds: 60},
		},
		Host: HostConfig{
			ProcPath: "/proc",
			Disk:     DiskConfig{Enabled: true, Paths: []string{"/"}, ThresholdPercent: 90},
			Memory:   ThresholdConfig{Enabled: true, ThresholdPercent: 90, ForSeconds: 300},
			CPU:      ThresholdConfig{Enabled: true, ThresholdPercent: 95, ForSeconds: 600},
		},
		Redact: RedactConfig{Defaults: true},
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

	h := c.Host
	if h.Disk.Enabled {
		if len(h.Disk.Paths) == 0 {
			return fmt.Errorf("host.disk.paths must list at least one path")
		}
		if err := checkThreshold("host.disk", h.Disk.ThresholdPercent, 0); err != nil {
			return err
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
	if (h.Memory.Enabled || h.CPU.Enabled) && h.ProcPath == "" {
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
