package detector

import (
	"strings"
	"testing"
	"time"
)

const mib = 1024 * 1024

func memSnap(usedMiB uint64) ContainerSnapshot {
	return ContainerSnapshot{ID: "c1", Name: "api", Status: "running", MemoryUsed: usedMiB * mib, MemoryLimit: 100 * mib}
}

func TestMemoryDetector_SustainAndHysteresis(t *testing.T) {
	d := NewMemoryDetector(90, time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }
	step := func(used uint64, after time.Duration) *Issue {
		now = now.Add(after)
		return d.Check(memSnap(used))
	}

	if step(50, 0) != nil {
		t.Fatal("alert below threshold")
	}
	if step(95, 0) != nil {
		t.Fatal("alert before the sustain period")
	}
	if step(95, 30*time.Second) != nil {
		t.Fatal("alert at half the sustain period")
	}
	// A dip below the threshold restarts the clock.
	step(80, 10*time.Second)
	if step(95, 10*time.Second) != nil || step(95, 50*time.Second) != nil {
		t.Fatal("dip below threshold should have reset the sustain clock")
	}

	issue := step(96, 15*time.Second)
	if issue == nil {
		t.Fatal("expected alert after sustained pressure")
	}
	if !strings.Contains(issue.Message, "96% of limit (96.0MiB / 100.0MiB)") {
		t.Errorf("message = %q", issue.Message)
	}

	// The episode lasts through the hysteresis band (85-90%)...
	if step(87, time.Minute) == nil {
		t.Fatal("episode ended inside the hysteresis band")
	}
	// ...and ends below 85%.
	if step(70, time.Minute) != nil {
		t.Fatal("episode should be over")
	}
	step(95, time.Second)
	if step(95, 2*time.Minute) == nil {
		t.Fatal("expected a new episode after recovering and climbing again")
	}
}

func TestMemoryDetector_ZeroSustainAlertsImmediately(t *testing.T) {
	d := NewMemoryDetector(90, 0)
	if d.Check(memSnap(90)) == nil {
		t.Fatal("expected immediate alert at exactly the threshold")
	}
}

func TestMemoryDetector_StoppedContainerStaysInEpisode(t *testing.T) {
	d := NewMemoryDetector(90, 0)
	d.Check(memSnap(99))
	stopped := ContainerSnapshot{ID: "c1", Name: "api", Status: "exited"}
	if d.Check(stopped) == nil {
		t.Fatal("stopping mid-episode shouldn't count as recovery")
	}
	// Back up and measured low: over.
	if d.Check(memSnap(10)) != nil {
		t.Fatal("episode should end once usage is measured low")
	}
}

func TestMemoryDetector_SkipsUnlimitedAndForgets(t *testing.T) {
	d := NewMemoryDetector(90, 0)
	if d.Check(ContainerSnapshot{ID: "c1", Status: "running", MemoryUsed: 99 * mib}) != nil {
		t.Fatal("container without a limit reported")
	}
	d.Check(memSnap(10))
	d.Forget("c1")
	if len(d.state) != 0 {
		t.Fatalf("state not dropped: %v", d.state)
	}
}

func TestFormatBytes(t *testing.T) {
	for in, want := range map[uint64]string{512: "512B", 1536: "1.5KiB", 64 * mib: "64.0MiB", 3 << 30: "3.0GiB"} {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
