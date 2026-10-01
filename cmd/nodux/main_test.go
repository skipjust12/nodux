package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/config"
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

func closeApp(a *app) {
	if a.webhook != nil {
		a.webhook.Close(context.Background())
	}
	if a.history != nil {
		a.history.Close()
	}
}

func TestBuild_Defaults(t *testing.T) {
	dir := t.TempDir()
	a, err := build(load(t, "state_dir: "+dir))
	if err != nil {
		t.Fatal(err)
	}
	defer closeApp(a)
	opts := a.opts
	if a.webhook != nil || opts.Analyzer != nil || a.llm != nil {
		t.Error("webhook/LLM should be off by default")
	}
	// crashloop is both a poll and an event detector; expected is on
	// even without names, for the nodux.expected label.
	want := []string{"crashloop", "unhealthy", "memory", "oom", "exit", "expected", "host_disk", "host_memory", "host_cpu", "docker"}
	if got := enabledNames(opts); !reflect.DeepEqual(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
	if len(opts.Detectors) != 3 || len(opts.EventDetectors) != 3 || !opts.CollectStats {
		t.Errorf("unexpected wiring: %d poll, %d event, stats=%v", len(opts.Detectors), len(opts.EventDetectors), opts.CollectStats)
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
  expected:
    containers: [db]
host:
  cpu: {enabled: false}
incidents:
  enabled: false
actions:
  webhook:
    enabled: true
    url: https://example.com/hook
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

	want := []string{"crashloop", "unhealthy", "exit", "expected", "host_disk", "host_memory", "docker"}
	if got := enabledNames(opts); !reflect.DeepEqual(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
	if opts.CollectStats || opts.Grouping.Enabled {
		t.Error("stats collected without the memory detector, or grouping on")
	}
	if a.webhook == nil || len(opts.Actions) != 2 || opts.Analyzer == nil || a.llm == nil {
		t.Errorf("webhook/LLM not wired: %+v", opts)
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
