package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/history"
)

type fakeSummarizer struct{ got string }

func (f *fakeSummarizer) SummarizeDigest(_ context.Context, digest string) (string, error) {
	f.got = digest
	return "Look at api first: it leaks memory.", nil
}

func TestBuild(t *testing.T) {
	store, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	to := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	from := to.Add(-24 * time.Hour)
	at := func(h int) time.Time { return from.Add(time.Duration(h) * time.Hour) }

	var alerts []history.Alert
	for i := 0; i < 5; i++ {
		alerts = append(alerts, history.Alert{Time: at(i + 1), State: "firing", Detector: "exit", Severity: "warning", Subject: "api", Container: true, Message: "exited", IncidentID: 1})
	}
	for i := 0; i < 3; i++ {
		alerts = append(alerts,
			history.Alert{Time: at(i + 2), State: "firing", Detector: "unhealthy", Severity: "warning", Subject: "worker", Container: true, Message: "failing", Episode: "unhealthy/w1", IncidentID: int64(2 + i)},
			history.Alert{Time: at(i + 3), State: "resolved", Detector: "unhealthy", Severity: "warning", Subject: "worker", Container: true, Message: "resolved", Episode: "unhealthy/w1", IncidentID: int64(2 + i)},
		)
	}
	alerts = append(alerts,
		history.Alert{Time: at(10), State: "firing", Detector: "host_disk", Severity: "critical", Subject: "/", Message: "disk full", Episode: "host_disk//"},
		history.Alert{Time: from.Add(-time.Hour), State: "firing", Detector: "oom", Severity: "critical", Subject: "api", Container: true, Message: "before the period"},
	)
	store.AddAlerts(ctx, alerts)

	var samples []history.MemorySample
	for i := 0; i < 24; i++ {
		used := uint64(200 << 20)
		if i >= 18 {
			used = 400 << 20
		}
		samples = append(samples,
			history.MemorySample{Time: at(i), Container: "api", Used: used, Limit: 1 << 30},
			history.MemorySample{Time: at(i), Container: "db", Used: 500 << 20},
		)
	}
	store.AddMemorySamples(ctx, samples)
	store.AddLLMCall(ctx, history.LLMCall{Time: at(1), Run: "r1", Purpose: "incident", Model: "claude-opus-5-5", Input: 1_000_000, Output: 10_000, CacheRead: 500_000})
	store.AddLLMCall(ctx, history.LLMCall{Time: at(1), Run: "r1", Purpose: "incident", Model: "claude-opus-5-5", Input: 1000})

	sum := &fakeSummarizer{}
	b := &Builder{
		History: store, Host: "vps1", Location: time.UTC, Summarizer: sum,
		OpenAlerts: func() []detector.Issue {
			return []detector.Issue{{Detector: "host_disk", Resource: "/", DetectedAt: to.Add(-3 * 24 * time.Hour)}}
		},
	}
	d, err := b.Build(ctx, "Daily digest", from, to)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"*nodux daily digest* for vps1, Sep 30 09:00 – Oct 1 09:00 UTC",
		"*Alerts:* 9 (1 critical) in 4 incidents, 3 resolutions",
		"• `api`: exit ×5",
		"• `worker`: unhealthy ×3",
		"*Host:* `/`: host_disk ×1",
		"*Flapping:* unhealthy `worker` opened 3 times",
		"*Still open:* host_disk `/` (3d)",
		"*Memory growing:* `api` 200.0MiB → 400.0MiB (+100%) of 1.0GiB limit",
		"*LLM:* 1 analyses in 2 requests, 1.5M input tokens (500k from cache), 10k output, about $4.30",
		"\n> Look at api first: it leaks memory.",
	} {
		if !strings.Contains(d.Text, want) {
			t.Errorf("missing %q in:\n%s", want, d.Text)
		}
	}
	if strings.Contains(d.Text, "db") || strings.Contains(d.Text, "before the period") {
		t.Errorf("unexpected content:\n%s", d.Text)
	}
	if !strings.Contains(sum.got, "*Alerts:*") || strings.Contains(sum.got, "Look at api") {
		t.Errorf("summarizer input = %q", sum.got)
	}
	r := d.Data.(*Report)
	if r.Alerts != 9 || r.Critical != 1 || len(r.Memory) != 1 || r.LLM.Runs != 1 || r.Takeaway == "" {
		t.Errorf("report = %+v", r)
	}
	if len(d.Text) > 1900 {
		t.Errorf("digest is %d bytes", len(d.Text))
	}
}

func TestBuild_QuietPeriodSkipsTakeaway(t *testing.T) {
	store, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sum := &fakeSummarizer{}
	b := &Builder{History: store, Summarizer: sum, Location: time.UTC}
	to := time.Now()
	d, err := b.Build(context.Background(), "Weekly digest", to.AddDate(0, 0, -7), to)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Text, "*nodux weekly digest*") || !strings.Contains(d.Text, "*Alerts:* none.") || sum.got != "" {
		t.Errorf("text = %q, summarizer called = %v", d.Text, sum.got != "")
	}
}

func TestSchedule(t *testing.T) {
	if _, err := ParseSchedule("hourly", "09:00", ""); err == nil {
		t.Error("bad every accepted")
	}
	if _, err := ParseSchedule("daily", "9", ""); err == nil {
		t.Error("bad at accepted")
	}
	if _, err := ParseSchedule("weekly", "09:00", "someday"); err == nil {
		t.Error("bad weekday accepted")
	}

	daily, err := ParseSchedule("daily", "09:00", "")
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Europe/Berlin")
	// Before 9: today. At or after 9: tomorrow.
	if got := daily.Next(time.Date(2026, 10, 1, 8, 59, 0, 0, loc)); !got.Equal(time.Date(2026, 10, 1, 9, 0, 0, 0, loc)) {
		t.Errorf("next = %v", got)
	}
	if got := daily.Next(time.Date(2026, 10, 1, 9, 0, 0, 0, loc)); !got.Equal(time.Date(2026, 10, 2, 9, 0, 0, 0, loc)) {
		t.Errorf("next = %v", got)
	}
	// Across the end of DST (Oct 25, 2026 in Berlin): still 09:00 local.
	if got := daily.Next(time.Date(2026, 10, 24, 10, 0, 0, 0, loc)); got.Hour() != 9 || got.Day() != 25 {
		t.Errorf("next across DST = %v", got)
	}
	from, to := daily.Period(time.Date(2026, 10, 2, 9, 0, 0, 0, loc))
	if !from.Equal(time.Date(2026, 10, 1, 9, 0, 0, 0, loc)) || to.Day() != 2 || daily.Title() != "Daily digest" {
		t.Errorf("period = %v – %v", from, to)
	}

	weekly, err := ParseSchedule("Weekly", "18:30", "fri")
	if err != nil {
		t.Fatal(err)
	}
	// Oct 1, 2026 is a Thursday.
	if got := weekly.Next(time.Date(2026, 10, 1, 20, 0, 0, 0, time.UTC)); !got.Equal(time.Date(2026, 10, 2, 18, 30, 0, 0, time.UTC)) {
		t.Errorf("weekly next = %v", got)
	}
	if got := weekly.Next(time.Date(2026, 10, 2, 18, 30, 0, 0, time.UTC)); !got.Equal(time.Date(2026, 10, 9, 18, 30, 0, 0, time.UTC)) {
		t.Errorf("weekly next after firing = %v", got)
	}
}
