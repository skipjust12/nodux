package detector

import (
	"testing"
	"time"
)

func TestCrashLoopDetector_TriggersAfterThreshold(t *testing.T) {
	d := NewCrashLoopDetector(3, 5*time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }

	snap := ContainerSnapshot{ID: "c1", Name: "flaky", RestartCount: 0}

	if issue := d.Check(snap); issue != nil {
		t.Fatalf("expected no issue on first sighting, got %+v", issue)
	}

	// Три рестарта подряд, укладывающиеся в окно.
	for i, restarts := range []int{1, 2} {
		now = now.Add(time.Second)
		snap.RestartCount = restarts
		if issue := d.Check(snap); issue != nil {
			t.Fatalf("unexpected issue at step %d: %+v", i, issue)
		}
	}

	now = now.Add(time.Second)
	snap.RestartCount = 3
	issue := d.Check(snap)
	if issue == nil {
		t.Fatalf("expected crashloop issue after 3 restarts, got nil")
	}
	if issue.Container.RestartCount != 3 {
		t.Errorf("expected restart count 3, got %d", issue.Container.RestartCount)
	}

	// Повторный Check с тем же RestartCount не должен алертить снова.
	if issue := d.Check(snap); issue != nil {
		t.Fatalf("expected no duplicate issue for same restart count, got %+v", issue)
	}
}

func TestCrashLoopDetector_OldRestartsExpireOutsideWindow(t *testing.T) {
	d := NewCrashLoopDetector(3, time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }

	snap := ContainerSnapshot{ID: "c1", Name: "flaky", RestartCount: 0}
	d.Check(snap) // seed

	now = now.Add(time.Second)
	snap.RestartCount = 1
	d.Check(snap)

	now = now.Add(time.Second)
	snap.RestartCount = 2
	d.Check(snap)

	// Уходим за пределы окна — старые два рестарта должны "истечь".
	now = now.Add(2 * time.Minute)
	snap.RestartCount = 3
	if issue := d.Check(snap); issue != nil {
		t.Fatalf("expected no issue once earlier restarts fell outside window, got %+v", issue)
	}
}

func TestCrashLoopDetector_IgnoresHealthyContainer(t *testing.T) {
	d := NewCrashLoopDetector(3, 5*time.Minute)
	snap := ContainerSnapshot{ID: "c1", Name: "stable", RestartCount: 0}

	for i := 0; i < 5; i++ {
		if issue := d.Check(snap); issue != nil {
			t.Fatalf("unexpected issue for container with no restarts: %+v", issue)
		}
	}
}
