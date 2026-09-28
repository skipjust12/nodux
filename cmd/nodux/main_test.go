package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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

func TestBuildOptions_Defaults(t *testing.T) {
	opts, webhook, err := buildOptions(load(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if webhook != nil || opts.Classifier != nil {
		t.Error("webhook/LLM should be off by default")
	}
	// crashloop is both a poll and an event detector; expected has no
	// containers configured, so it's not wired in.
	want := []string{"crashloop", "unhealthy", "memory", "oom", "exit", "host_disk", "host_memory", "host_cpu", "docker"}
	if got := enabledNames(opts); !reflect.DeepEqual(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
	if len(opts.Detectors) != 3 || len(opts.EventDetectors) != 3 || !opts.CollectStats {
		t.Errorf("unexpected wiring: %d poll, %d event, stats=%v", len(opts.Detectors), len(opts.EventDetectors), opts.CollectStats)
	}
	if opts.Redactor == nil || len(opts.Actions) != 1 || opts.Actions[0].Name() != "console" {
		t.Errorf("redactor/actions: %+v", opts)
	}
}

func TestBuildOptions_EverythingOn(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	opts, webhook, err := buildOptions(load(t, `
detectors:
  oom: {enabled: false}
  memory: {enabled: false}
  expected:
    containers: [db]
host:
  cpu: {enabled: false}
actions:
  webhook:
    enabled: true
    url: https://example.com/hook
llm:
  enabled: true
`))
	if err != nil {
		t.Fatal(err)
	}
	defer webhook.Close(context.Background())

	want := []string{"crashloop", "unhealthy", "exit", "expected", "host_disk", "host_memory", "docker"}
	if got := enabledNames(opts); !reflect.DeepEqual(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
	if opts.CollectStats {
		t.Error("stats collected without the memory detector")
	}
	if webhook == nil || len(opts.Actions) != 2 || opts.Classifier == nil {
		t.Errorf("webhook/LLM not wired: %+v", opts)
	}
}
