package detector

import (
	"strings"
	"testing"
)

func TestUnhealthyDetector_AlertsOncePerEpisode(t *testing.T) {
	d := NewUnhealthyDetector()
	snap := ContainerSnapshot{ID: "c1", Name: "web", HealthStatus: "healthy"}

	if issue := d.Check(snap); issue != nil {
		t.Fatalf("healthy container reported: %+v", issue)
	}

	snap.HealthStatus = "unhealthy"
	snap.HealthFailingStreak = 3
	snap.HealthLastOutput = "curl: (7) Failed to connect\n"
	issue := d.Check(snap)
	if issue == nil {
		t.Fatal("expected issue for unhealthy container")
	}
	if issue.Severity != SeverityWarning {
		t.Errorf("severity = %q", issue.Severity)
	}
	if !strings.Contains(issue.Message, "3 consecutive failures") || !strings.Contains(issue.Message, "Failed to connect") {
		t.Errorf("message missing details: %q", issue.Message)
	}

	if issue := d.Check(snap); issue != nil {
		t.Fatalf("duplicate alert within the same episode: %+v", issue)
	}

	// Recovers, then breaks again: that's a new episode.
	snap.HealthStatus = "healthy"
	d.Check(snap)
	snap.HealthStatus = "unhealthy"
	if issue := d.Check(snap); issue == nil {
		t.Fatal("expected a new alert for a new unhealthy episode")
	}
}

func TestUnhealthyDetector_ReportsOnFirstSight(t *testing.T) {
	d := NewUnhealthyDetector()
	if issue := d.Check(ContainerSnapshot{ID: "c1", HealthStatus: "unhealthy"}); issue == nil {
		t.Fatal("already-unhealthy container should be reported on first sight")
	}
}

func TestUnhealthyDetector_IgnoresNoHealthcheckAndStarting(t *testing.T) {
	d := NewUnhealthyDetector()
	for _, status := range []string{"", "starting", "healthy"} {
		if issue := d.Check(ContainerSnapshot{ID: "c1", HealthStatus: status}); issue != nil {
			t.Errorf("status %q reported: %+v", status, issue)
		}
	}
}

func TestUnhealthyDetector_TruncatesLongOutput(t *testing.T) {
	d := NewUnhealthyDetector()
	issue := d.Check(ContainerSnapshot{ID: "c1", HealthStatus: "unhealthy", HealthLastOutput: strings.Repeat("x", 5000)})
	if issue == nil {
		t.Fatal("expected issue")
	}
	if len(issue.Message) > maxHealthOutput+100 {
		t.Errorf("message not truncated: %d bytes", len(issue.Message))
	}
}
