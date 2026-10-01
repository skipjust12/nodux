package config

import (
	"log/slog"
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
	if !d.CrashLoop.Enabled || !d.OOM.Enabled || !d.Unhealthy.Enabled || !d.Exit.Enabled || !d.Memory.Enabled || !d.Expected.Enabled {
		t.Errorf("example config should enable every detector: %+v", d)
	}
	if !cfg.Host.Disk.Enabled || !cfg.Host.Memory.Enabled || !cfg.Host.CPU.Enabled {
		t.Errorf("example config should enable host checks: %+v", cfg.Host)
	}
	if cfg.AlertCooldown() != 10*time.Minute {
		t.Errorf("cooldown = %s", cfg.AlertCooldown())
	}
}

func TestLoad_EmptyFileGivesDefaults(t *testing.T) {
	cfg, err := Load(write(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Hostname, _ = os.Hostname()
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("empty file:\n got %+v\nwant %+v", cfg, want)
	}
	d := cfg.Detectors
	if !d.CrashLoop.Enabled || !d.OOM.Enabled || !d.Unhealthy.Enabled || !d.Exit.Enabled || !d.Memory.Enabled {
		t.Error("detectors should be on unless turned off")
	}
	if cfg.Actions.Webhook.Enabled || cfg.Heartbeat.Enabled || cfg.LLM.Enabled {
		t.Error("nothing should leave the host by default")
	}
	if cfg.PollInterval() != 15*time.Second || cfg.DockerDownAfter() != time.Minute || cfg.SlogLevel() != slog.LevelInfo {
		t.Errorf("bad defaults: %+v", cfg)
	}
}

func TestLoad_PartialOverridesKeepOtherDefaults(t *testing.T) {
	cfg, err := Load(write(t, `
hostname: vps1
log_level: debug
detectors:
  oom:
    enabled: false
  memory:
    threshold_percent: 80
host:
  disk:
    paths: [/, /var/lib/docker]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "vps1" || cfg.SlogLevel() != slog.LevelDebug {
		t.Errorf("hostname/log level: %q %v", cfg.Hostname, cfg.SlogLevel())
	}
	if cfg.Detectors.OOM.Enabled {
		t.Error("explicit enabled: false ignored")
	}
	m := cfg.Detectors.Memory
	if !m.Enabled || m.ThresholdPercent != 80 || m.For() != time.Minute {
		t.Errorf("memory = %+v", m)
	}
	if !reflect.DeepEqual(cfg.Host.Disk.Paths, []string{"/", "/var/lib/docker"}) || cfg.Host.Disk.ThresholdPercent != 90 {
		t.Errorf("disk = %+v", cfg.Host.Disk)
	}
}

func TestLoad_ExplicitZerosAndEmptyListsKept(t *testing.T) {
	cfg, err := Load(write(t, `
alert_cooldown_minutes: 0
docker:
  down_alert_after_seconds: 0
detectors:
  exit:
    ignore_exit_codes: []
  memory:
    for_seconds: 0
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AlertCooldown() != 0 || cfg.DockerDownAfter() != 0 || cfg.Detectors.Memory.For() != 0 {
		t.Errorf("explicit 0 should be kept: %+v", cfg)
	}
	if len(cfg.Detectors.Exit.IgnoreExitCodes) != 0 {
		t.Errorf("explicit [] should be kept, got %v", cfg.Detectors.Exit.IgnoreExitCodes)
	}
}

func TestLoad_Errors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key (typo)":     "detectors:\n  crashloop:\n    restart_treshold: 5\n",
		"unknown top-level key":  "pol_interval_seconds: 5\n",
		"zero poll interval":     "poll_interval_seconds: 0\n",
		"negative cooldown":      "alert_cooldown_minutes: -1\n",
		"bad log level":          "log_level: loud\n",
		"bad yaml":               "poll_interval_seconds: [\n",
		"crashloop threshold 0":  "detectors:\n  crashloop:\n    restart_threshold: 0\n",
		"memory threshold > 100": "detectors:\n  memory:\n    threshold_percent: 150\n",
		"memory negative for":    "detectors:\n  memory:\n    for_seconds: -5\n",
		"disk without paths":     "host:\n  disk:\n    paths: []\n",
		"cpu threshold 0":        "host:\n  cpu:\n    threshold_percent: 0\n",
		"bad redact pattern":     "redact:\n  patterns: ['(']\n",
		"webhook without url":    "actions:\n  webhook:\n    enabled: true\n",
		"webhook bad scheme":     "actions:\n  webhook:\n    enabled: true\n    url: ftp://x\n",
		"webhook bad format":     "actions:\n  webhook:\n    enabled: true\n    url: https://x\n    format: teams\n",
		"heartbeat without url":  "heartbeat:\n  enabled: true\n",
		"llm without key":        "llm:\n  enabled: true\n  api_key: ''\n",
		"llm bad effort":         "llm:\n  enabled: true\n  api_key: k\n  effort: extreme\n",
		"llm too many steps":     "llm:\n  enabled: true\n  api_key: k\n  max_steps: 50\n",
		"relative state_dir":     "state_dir: state\n",
		"zero retention":         "history:\n  retention_days: 0\n",
		"incident window 0":      "incidents:\n  window_minutes: 0\n",
		"digest without state":   "state_dir: ''\ndigest:\n  enabled: true\n",
		"digest bad time":        "digest:\n  enabled: true\n  at: '25:00'\n",
		"digest bad weekday":     "digest:\n  enabled: true\n  every: weekly\n  weekday: someday\n",
		"telegram without token": "chatops:\n  telegram:\n    enabled: true\n    token: ''\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Load("/nonexistent.yaml"); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("missing file: %v", err)
	}
}

func TestLoad_ExpandsEnv(t *testing.T) {
	t.Setenv("NODUX_TEST_HOOK", "hooks.example.com/abc")
	t.Setenv("NODUX_TEST_TOKEN", "s3cret")
	t.Setenv("NODUX_TEST_HC", "uuid")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	cfg, err := Load(write(t, `
actions:
  webhook:
    enabled: true
    url: https://${NODUX_TEST_HOOK}
    format: slack
    headers:
      Authorization: Bearer $NODUX_TEST_TOKEN
heartbeat:
  enabled: true
  url: https://hc-ping.com/${NODUX_TEST_HC}
llm:
  enabled: true
`))
	if err != nil {
		t.Fatal(err)
	}
	wh := cfg.Actions.Webhook
	if wh.URL != "https://hooks.example.com/abc" || wh.Headers["Authorization"] != "Bearer s3cret" {
		t.Errorf("webhook env not expanded: %+v", wh)
	}
	if cfg.Heartbeat.URL != "https://hc-ping.com/uuid" || cfg.LLM.APIKey != "sk-ant-test" {
		t.Errorf("heartbeat/llm env not expanded: %q %q", cfg.Heartbeat.URL, cfg.LLM.APIKey)
	}
}

func TestLoad_NewSectionsDefaults(t *testing.T) {
	t.Setenv("NODUX_TELEGRAM_TOKEN", "123:abc")
	cfg, err := Load(write(t, "chatops:\n  telegram:\n    enabled: true\n    allowed_chat_ids: [42, -100123]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != "/var/lib/nodux" || cfg.History.Retention() != 30*24*time.Hour {
		t.Errorf("state/history defaults: %q %v", cfg.StateDir, cfg.History.Retention())
	}
	if in := cfg.Incidents; !in.Enabled || in.GroupWait() != 30*time.Second || in.Window() != 10*time.Minute {
		t.Errorf("incidents = %+v", in)
	}
	if l := cfg.LLM; l.Effort != "low" || l.MaxSteps != 4 || l.Timeout() != 90*time.Second {
		t.Errorf("llm = %+v", l)
	}
	if tg := cfg.ChatOps.Telegram; tg.Token != "123:abc" || !reflect.DeepEqual(tg.AllowedChatIDs, []int64{42, -100123}) {
		t.Errorf("telegram = %+v", tg)
	}
	if d := cfg.Digest; d.Enabled || d.Every != "daily" || d.At != "09:00" {
		t.Errorf("digest = %+v", d)
	}
}

func TestLoad_MissingEnvIsAnError(t *testing.T) {
	t.Setenv("NODUX_TEST_EMPTY", "")
	_, err := Load(write(t, `
actions:
  webhook:
    enabled: true
    url: https://hooks.slack.com/services/${NODUX_TEST_UNSET_PATH}
    headers:
      X-Token: $NODUX_TEST_EMPTY
`))
	if err == nil {
		t.Fatal("expected an error for unset variables")
	}
	for _, want := range []string{"$NODUX_TEST_UNSET_PATH (in actions.webhook.url)", "$NODUX_TEST_EMPTY (in actions.webhook.headers.X-Token)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q doesn't mention %q", err, want)
		}
	}

	// Disabled features aren't expanded, so their variables may be unset.
	if _, err := Load(write(t, "actions:\n  webhook:\n    url: https://x/${NODUX_TEST_UNSET_PATH}\n")); err != nil {
		t.Errorf("disabled webhook: %v", err)
	}
}

func TestLoad_InvalidURLErrorDoesNotEchoSecrets(t *testing.T) {
	_, err := Load(write(t, "actions:\n  webhook:\n    enabled: true\n    url: hooks.slack.com/services/T0/B0/SECRET\n"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}
