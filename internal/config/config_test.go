package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_ExampleConfig(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("example config doesn't load: %v", err)
	}
	d := cfg.Detectors
	if !d.CrashLoop.Enabled || !d.OOM.Enabled || !d.Unhealthy.Enabled || !d.Exit.Enabled {
		t.Errorf("example config should enable every detector: %+v", d)
	}
	if cfg.AlertCooldown() != 10*time.Minute {
		t.Errorf("cooldown = %s", cfg.AlertCooldown())
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(write(t, "detectors:\n  exit:\n    enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval() != 15*time.Second || cfg.Docker.SocketPath != "/var/run/docker.sock" {
		t.Errorf("bad defaults: %+v", cfg)
	}
	if cfg.AlertCooldown() != 10*time.Minute {
		t.Errorf("cooldown default = %s", cfg.AlertCooldown())
	}
	if !reflect.DeepEqual(cfg.Detectors.Exit.IgnoreExitCodes, []int{0}) {
		t.Errorf("ignore_exit_codes default = %v", cfg.Detectors.Exit.IgnoreExitCodes)
	}
	if cfg.Detectors.OOM.Enabled {
		t.Error("detectors not mentioned in the config must stay disabled")
	}
}

func TestLoad_ExplicitZeroCooldownAndEmptyIgnoreList(t *testing.T) {
	cfg, err := Load(write(t, "alert_cooldown_minutes: 0\ndetectors:\n  exit:\n    ignore_exit_codes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AlertCooldown() != 0 {
		t.Errorf("explicit 0 should disable cooldown, got %s", cfg.AlertCooldown())
	}
	if len(cfg.Detectors.Exit.IgnoreExitCodes) != 0 {
		t.Errorf("explicit [] should be kept, got %v", cfg.Detectors.Exit.IgnoreExitCodes)
	}
}

func TestLoad_Errors(t *testing.T) {
	for name, body := range map[string]string{
		"negative cooldown": "alert_cooldown_minutes: -1\n",
		"bad yaml":          "poll_interval_seconds: [\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Load("/nonexistent.yaml"); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("missing file: %v", err)
	}
}
