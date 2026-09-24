package config

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config describes the contents of config.yaml.
type Config struct {
	PollIntervalSeconds int `yaml:"poll_interval_seconds"`
	// AlertCooldownMinutes suppresses repeat alerts from the same
	// detector for the same container name. nil means "use the default";
	// 0 disables the cooldown.
	AlertCooldownMinutes *int            `yaml:"alert_cooldown_minutes"`
	Docker               DockerConfig    `yaml:"docker"`
	ExcludeContainers    []string        `yaml:"exclude_containers"`
	Detectors            DetectorsConfig `yaml:"detectors"`
	Actions              ActionsConfig   `yaml:"actions"`
	LLM                  LLMConfig       `yaml:"llm"`
}

type DockerConfig struct {
	SocketPath string `yaml:"socket_path"`
}

type DetectorsConfig struct {
	CrashLoop CrashLoopConfig `yaml:"crashloop"`
	OOM       ToggleConfig    `yaml:"oom"`
	Unhealthy ToggleConfig    `yaml:"unhealthy"`
	Exit      ExitConfig      `yaml:"exit"`
	Memory    MemoryConfig    `yaml:"memory"`
}

type MemoryConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent"`
	// ForSeconds is how long usage must stay above the threshold. nil
	// means the default (60); 0 alerts on the first sample.
	ForSeconds *int `yaml:"for_seconds"`
}

type ActionsConfig struct {
	Webhook WebhookConfig `yaml:"webhook"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Format  string `yaml:"format"` // json (default) or slack
	// Values may reference environment variables ($VAR / ${VAR}), so
	// tokens don't have to live in the config file.
	Headers        map[string]string `yaml:"headers"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
}

// ToggleConfig is for detectors that have nothing to tune.
type ToggleConfig struct {
	Enabled bool `yaml:"enabled"`
}

type ExitConfig struct {
	Enabled bool `yaml:"enabled"`
	// Exit codes that are never reported. nil means the default ([0]).
	IgnoreExitCodes []int `yaml:"ignore_exit_codes"`
}

type CrashLoopConfig struct {
	Enabled          bool `yaml:"enabled"`
	RestartThreshold int  `yaml:"restart_threshold"`
	WindowMinutes    int  `yaml:"window_minutes"`
}

// LLMConfig is groundwork for the future: enabling an optional LLM layer
// for classifying ambiguous detector hits. For now the field is only
// read and passed to NoopClassifier — there's no real logic behind it yet.
type LLMConfig struct {
	Enabled bool `yaml:"enabled"`
}

func (c *Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSeconds) * time.Second
}

func (c *Config) AlertCooldown() time.Duration {
	return time.Duration(*c.AlertCooldownMinutes) * time.Minute
}

func (c *MemoryConfig) For() time.Duration {
	return time.Duration(*c.ForSeconds) * time.Second
}

func (c *WebhookConfig) Timeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func (c *CrashLoopConfig) Window() time.Duration {
	return time.Duration(c.WindowMinutes) * time.Minute
}

// Load reads and validates the config from the given file, filling in
// defaults for any fields that were left unset.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	applyDefaults(cfg)

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}

	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.PollIntervalSeconds <= 0 {
		cfg.PollIntervalSeconds = 15
	}
	if cfg.AlertCooldownMinutes == nil {
		def := 10
		cfg.AlertCooldownMinutes = &def
	}
	if cfg.Docker.SocketPath == "" {
		cfg.Docker.SocketPath = "/var/run/docker.sock"
	}
	if cfg.Detectors.Exit.IgnoreExitCodes == nil {
		cfg.Detectors.Exit.IgnoreExitCodes = []int{0}
	}
	if cfg.Detectors.Memory.ThresholdPercent == 0 {
		cfg.Detectors.Memory.ThresholdPercent = 90
	}
	if cfg.Detectors.Memory.ForSeconds == nil {
		def := 60
		cfg.Detectors.Memory.ForSeconds = &def
	}

	wh := &cfg.Actions.Webhook
	wh.URL = os.ExpandEnv(wh.URL)
	for k, v := range wh.Headers {
		wh.Headers[k] = os.ExpandEnv(v)
	}
	if wh.Format == "" {
		wh.Format = "json"
	}
	if wh.TimeoutSeconds <= 0 {
		wh.TimeoutSeconds = 5
	}
	if cfg.Detectors.CrashLoop.RestartThreshold <= 0 {
		cfg.Detectors.CrashLoop.RestartThreshold = 3
	}
	if cfg.Detectors.CrashLoop.WindowMinutes <= 0 {
		cfg.Detectors.CrashLoop.WindowMinutes = 5
	}
}

func (c *Config) validate() error {
	if c.PollIntervalSeconds <= 0 {
		return fmt.Errorf("poll_interval_seconds must be positive")
	}
	if *c.AlertCooldownMinutes < 0 {
		return fmt.Errorf("alert_cooldown_minutes must not be negative")
	}
	if c.Docker.SocketPath == "" {
		return fmt.Errorf("docker.socket_path must not be empty")
	}
	if c.Detectors.CrashLoop.Enabled {
		if c.Detectors.CrashLoop.RestartThreshold <= 0 {
			return fmt.Errorf("detectors.crashloop.restart_threshold must be positive")
		}
		if c.Detectors.CrashLoop.WindowMinutes <= 0 {
			return fmt.Errorf("detectors.crashloop.window_minutes must be positive")
		}
	}
	if m := c.Detectors.Memory; m.Enabled {
		if m.ThresholdPercent <= 0 || m.ThresholdPercent > 100 {
			return fmt.Errorf("detectors.memory.threshold_percent must be in (0, 100]")
		}
		if *m.ForSeconds < 0 {
			return fmt.Errorf("detectors.memory.for_seconds must not be negative")
		}
	}
	if wh := c.Actions.Webhook; wh.Enabled {
		u, err := url.Parse(wh.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("actions.webhook.url must be an http(s) URL, got %q", wh.URL)
		}
		if wh.Format != "json" && wh.Format != "slack" {
			return fmt.Errorf("actions.webhook.format must be json or slack, got %q", wh.Format)
		}
	}
	return nil
}
