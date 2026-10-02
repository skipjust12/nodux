package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/config"
	"github.com/skipjust12/nodux/internal/engine"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/server"
	"github.com/skipjust12/nodux/internal/silence"
)

func load(t *testing.T, body string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func closeApp(a *app) { a.close() }

func TestBuild_Defaults(t *testing.T) {
	dir := t.TempDir()
	a, err := build(load(t, "state_dir: "+dir))
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(a)
	opts := a.opts
	if len(a.receivers) != 0 || opts.Analyzer != nil || a.llm != nil {
		t.Error("receivers/LLM should be off by default")
	}
	// crashloop and unhealthy are both poll and event detectors; expected
	// is on even without names, for the nodux.expected label; there are
	// no probes.
	want := []string{"crashloop", "unhealthy", "memory", "cpu_throttle", "oom", "exit", "expected",
		"host_disk", "host_disk_forecast", "host_memory", "host_cpu", "host_pressure", "host_oom", "docker"}
	if got := enabledNames(opts); !reflect.DeepEqual(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
	if len(opts.Detectors) != 4 || len(opts.EventDetectors) != 4 || !opts.CollectStats || !opts.CollectThrottling {
		t.Errorf("unexpected wiring: %d poll, %d event, stats=%v/%v", len(opts.Detectors), len(opts.EventDetectors), opts.CollectStats, opts.CollectThrottling)
	}
	if opts.Silences == nil || opts.DeployGrace != 2*time.Minute {
		t.Errorf("silences: %v %s", opts.Silences, opts.DeployGrace)
	}
	if opts.Redactor == nil || len(opts.Actions) != 1 || opts.Actions[0].Name() != "console" {
		t.Errorf("redactor/actions: %+v", opts)
	}
	if opts.State == nil || opts.History == nil || opts.SampleInterval != sampleInterval || !opts.Grouping.Enabled {
		t.Errorf("state/history/grouping not wired: %+v", opts)
	}
	for _, f := range []string{"state.json", "history.db"} {
		if _, err := os.Stat(filepath.Join(dir, f)); f == "history.db" && err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestBuild_EverythingOn(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("NODUX_TELEGRAM_TOKEN", "123:abc")
	a, err := build(load(t, `
state_dir: `+t.TempDir()+`
detectors:
  oom: {enabled: false}
  memory: {enabled: false}
  cpu_throttle: {enabled: false}
  expected:
    containers: [db]
host:
  cpu: {enabled: false}
  pressure: {cpu_some_percent: 50, memory_some_percent: 0, io_full_percent: 0}
  disk:
    forecast: {enabled: false}
probes:
  targets:
    - {name: api, url: "https://example.com/health", container: api}
    - {name: pg, tcp: "127.0.0.1:5432"}
incidents:
  enabled: false
actions:
  webhook:
    enabled: true
    url: https://example.com/hook
  receivers:
    - name: oncall
      type: telegram
      bot_token: ${NODUX_TELEGRAM_TOKEN}
      chat_id: "-100"
      severities: [critical]
    - name: phone
      type: ntfy
      url: https://ntfy.sh/topic
      send_resolved: false
      digest: false
    - name: team
      type: webhook
      url: https://example.com/slack
      format: slack
      severities: [warning]
silences:
  deploy_grace_seconds: 0
llm:
  enabled: true
  max_steps: 2
digest:
  enabled: true
  every: weekly
chatops:
  telegram:
    enabled: true
    allowed_chat_ids: [42]
`))
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(a)
	opts := a.opts

	want := []string{"crashloop", "unhealthy", "exit", "expected", "host_disk", "host_memory", "host_pressure", "host_oom", "probe", "tls_cert", "docker"}
	if got := enabledNames(opts); !reflect.DeepEqual(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
	if opts.CollectStats || opts.CollectThrottling || opts.Grouping.Enabled {
		t.Error("stats collected without the detectors that need them, or grouping on")
	}
	var names []string
	for _, r := range a.receivers {
		names = append(names, r.Name())
	}
	if !reflect.DeepEqual(names, []string{"webhook", "oncall", "phone", "team"}) || len(opts.Actions) != 5 {
		t.Errorf("receivers = %v, actions = %d", names, len(opts.Actions))
	}
	if opts.Analyzer == nil || a.llm == nil || opts.ProbeInterval != 30*time.Second || opts.DeployGrace != 0 {
		t.Errorf("LLM/probes/deploy grace not wired: %+v", opts)
	}
	if names := a.toolbox.Tools(); len(names) != 7 {
		t.Errorf("tools = %+v", names)
	}
}

func TestBuild_StateDirMustBeWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	_, err := build(load(t, "state_dir: "+filepath.Join(dir, "state")))
	if err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuild_NoStateDir(t *testing.T) {
	a, err := build(load(t, `state_dir: ""`))
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(a)
	if a.opts.State != nil || a.opts.History != nil || a.history != nil {
		t.Error("state kept on disk with state_dir off")
	}
}

func TestDigestNow(t *testing.T) {
	dir := t.TempDir()
	cfg := load(t, "state_dir: "+dir+"\nhostname: vps1\n")
	text, err := digestNow(context.Background(), cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "*nodux daily digest* for vps1") || !strings.Contains(text, "*Alerts:* none.") {
		t.Errorf("digest = %q", text)
	}
	if _, err := digestNow(context.Background(), load(t, `state_dir: ""`), time.Now()); err == nil {
		t.Error("digest without history should fail")
	}
}

func TestSince(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{
		45 * time.Second: "45s", 12 * time.Minute: "12m", 3*time.Hour + 5*time.Minute: "3h5m", 50 * time.Hour: "2d2h", -time.Hour: "0s",
	} {
		if got := since(now, now.Add(-d)); got != want {
			t.Errorf("since(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestParseCLI(t *testing.T) {
	a, err := parseCLI([]string{"api", "--socket", "/tmp/s.sock", "30m", "-c", "deploy", "--json"})
	if err != nil || a.socket != "/tmp/s.sock" || a.comment != "deploy" || !a.json || !reflect.DeepEqual(a.positional, []string{"api", "30m"}) {
		t.Fatalf("got %+v, %v", a, err)
	}
	if a, err := parseCLI([]string{"--comment=x y"}); err != nil || a.comment != "x y" {
		t.Fatalf("got %+v, %v", a, err)
	}
	if _, err := parseCLI([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if _, err := parseCLI([]string{"-c"}); err == nil {
		t.Fatal("missing value accepted")
	}
}

func TestPrintStatus(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	last := now.Add(-4 * time.Second)
	st := &server.Status{
		Host: "vps1", Version: "v1", Started: now.Add(-3 * time.Hour), DockerUp: true, LastPoll: &last,
		Episodes: []engine.Episode{
			{Detector: "crashloop", Severity: "critical", Container: "api", Message: "restarted 3 times", Since: now.Add(-12 * time.Minute)},
			{Detector: "host_disk", Severity: "critical", Resource: "/", Message: "disk / at 95%", Since: now.Add(-time.Hour), Silenced: true},
		},
		Silences:  []silence.Silence{{ID: "ab12", Matcher: silence.Matcher{Target: "/"}, Until: now.Add(28 * time.Minute), Comment: "cleanup"}},
		Receivers: []server.ReceiverStatus{{Name: "oncall", DeliveryStats: action.DeliveryStats{Sent: 3}}},
		LLM:       &llm.Budget{MaxPerHour: 30, Remaining: 29, OK: 1},
	}
	var b strings.Builder
	printStatus(&b, st, now)
	out := b.String()
	for _, want := range []string{
		"nodux v1 on vps1, up 3h0m; docker up, last poll 4s ago",
		"critical  crashloop  api      12m",
		"disk / at 95% [silenced]",
		"ab12  /      28m      cleanup",
		"oncall  3     0       0        0",
		"LLM: 29 of 30 calls left this hour; 1 ok, 0 failed, 0 skipped over budget",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
