package detector

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUnhealthyDetector_LevelTriggered(t *testing.T) {
	d := NewUnhealthyDetector()
	snap := ContainerSnapshot{ID: "c1", Name: "web", Status: "running", HealthStatus: "healthy"}

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
	// Still unhealthy: still reported (the engine deduplicates).
	if d.Check(snap) == nil {
		t.Fatal("Check must keep reporting while the problem lasts")
	}
}

func TestUnhealthyDetector_IgnoresNoHealthcheckAndStarting(t *testing.T) {
	d := NewUnhealthyDetector()
	for _, status := range []string{"", "starting", "healthy"} {
		if issue := d.Check(ContainerSnapshot{ID: "c1", Status: "running", HealthStatus: status}); issue != nil {
			t.Errorf("status %q reported: %+v", status, issue)
		}
	}
}

// Docker 29 reports a stopped container with a healthcheck as
// unhealthy (FailingStreak 0), e.g. after docker stop.
func TestUnhealthyDetector_IgnoresStoppedContainers(t *testing.T) {
	d := NewUnhealthyDetector()
	if issue := d.Check(ContainerSnapshot{ID: "c1", Status: "exited", HealthStatus: "unhealthy"}); issue != nil {
		t.Fatalf("stopped container reported: %+v", issue)
	}
}

func TestUnhealthyDetector_TruncatesLongOutput(t *testing.T) {
	d := NewUnhealthyDetector()
	issue := d.Check(ContainerSnapshot{ID: "c1", Status: "running", HealthStatus: "unhealthy", HealthLastOutput: strings.Repeat("я", 5000)})
	if issue == nil {
		t.Fatal("expected issue")
	}
	if len(issue.Message) > maxHealthOutput+100 {
		t.Errorf("message not truncated: %d bytes", len(issue.Message))
	}
	if !utf8.ValidString(issue.Message) {
		t.Error("truncation split a UTF-8 sequence")
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	if got := Truncate("abcdef", 3); got != "abc…" {
		t.Errorf("got %q", got)
	}
	if got := Truncate("яяя", 3); got != "я…" {
		t.Errorf("got %q", got)
	}
}
