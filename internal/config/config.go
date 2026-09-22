package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config describes the contents of config.yaml.
type Config struct {
	PollIntervalSeconds int             `yaml:"poll_interval_seconds"`
	Docker              DockerConfig    `yaml:"docker"`
	ExcludeContainers   []string        `yaml:"exclude_containers"`
	Detectors           DetectorsConfig `yaml:"detectors"`
	LLM                 LLMConfig       `yaml:"llm"`
}

type DockerConfig struct {
	SocketPath string `yaml:"socket_path"`
}

type DetectorsConfig struct {
	CrashLoop CrashLoopConfig `yaml:"crashloop"`
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
	if cfg.Docker.SocketPath == "" {
		cfg.Docker.SocketPath = "/var/run/docker.sock"
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
	return nil
}
