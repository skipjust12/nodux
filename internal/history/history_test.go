package history

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestStore_AlertsRoundTripAndQuery(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	exit := detector.Issue{
		Detector: "exit", Severity: "warning", Message: "container exited unexpectedly with code 1",
		Container:  detector.ContainerSnapshot{ID: "c1", Name: "api", ExitCode: 1, Image: "api:2"},
		Host:       "vps1",
		DetectedAt: base,
		IncidentID: 7,
	}
	resolved := detector.Issue{Detector: "host_disk", Severity: "critical", Resource: "/", Message: "resolved after 5m", Resolved: true, DetectedAt: base.Add(time.Hour), Key: "host_disk//"}
	if err := s.AddAlerts(ctx, []Alert{AlertFromIssue(exit, "db is down"), AlertFromIssue(resolved, "")}); err != nil {
		t.Fatal(err)
	}

	all, err := s.Alerts(ctx, Query{})
	if err != nil || len(all) != 2 {
		t.Fatalf("alerts = %+v, %v", all, err)
	}
	if all[0].Subject != "/" || all[0].State != "resolved" || all[0].Container || all[0].ExitCode != nil || all[0].Episode != "host_disk//" {
		t.Errorf("newest first, host alert: %+v", all[0])
	}
	a := all[1]
	if a.Subject != "api" || !a.Container || a.ExitCode == nil || *a.ExitCode != 1 || a.Analysis != "db is down" ||
		a.IncidentID != 7 || a.Image != "api:2" || !a.Time.Equal(base) || a.Host != "vps1" {
		t.Errorf("container alert: %+v", a)
	}

	got, _ := s.Alerts(ctx, Query{Subject: "api", Since: base, Until: base.Add(time.Minute), FiringOnly: true, Limit: 5})
	if len(got) != 1 {
		t.Errorf("filtered = %+v", got)
	}
	if got, _ := s.Alerts(ctx, Query{Since: base.Add(time.Minute)}); len(got) != 1 || got[0].Subject != "/" {
		t.Errorf("since filter = %+v", got)
	}

	if info, err := os.Stat(filepath.Join(dir, fileName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("db file: %v %v", info, err)
	}
}

func TestStore_ReopenKeepsDataAndSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.AddLLMCall(context.Background(), LLMCall{Run: "r1", Purpose: "incident", Model: "claude-opus-5-5", Input: 100, Output: 20})
	s.Close()

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	calls, err := s.LLMCalls(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || len(calls) != 1 || calls[0].Input != 100 || calls[0].Model != "claude-opus-5-5" {
		t.Fatalf("calls = %+v, %v", calls, err)
	}
}

func TestStore_MemorySamplesAndPrune(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := time.Now()
	s.now = func() time.Time { return now }

	s.AddMemorySamples(ctx, []MemorySample{
		{Time: now.Add(-20 * 24 * time.Hour), Container: "api", Used: 1},
		{Time: now.Add(-2 * time.Hour), Container: "api", Used: 100, Limit: 200},
		{Time: now.Add(-time.Hour), Container: "api", Used: 150, Limit: 200},
		{Time: now.Add(-time.Hour), Container: "db", Used: 500},
	})
	s.AddAlerts(ctx, []Alert{
		{Time: now.Add(-40 * 24 * time.Hour), State: "firing", Detector: "exit", Severity: "warning", Message: "old"},
		{Time: now.Add(-time.Hour), State: "firing", Detector: "exit", Severity: "warning", Message: "new"},
	})

	if err := s.Prune(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	samples, err := s.MemorySamples(ctx, now.Add(-30*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples["api"]) != 2 || samples["api"][0].Used != 100 || samples["api"][1].Limit != 200 || len(samples["db"]) != 1 {
		t.Errorf("samples = %+v", samples)
	}
	alerts, _ := s.Alerts(ctx, Query{})
	if len(alerts) != 1 || alerts[0].Message != "new" {
		t.Errorf("alerts after prune = %+v", alerts)
	}
}
