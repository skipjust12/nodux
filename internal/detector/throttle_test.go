package detector

import (
	"strings"
	"testing"
	"time"
)

func TestThrottleDetector(t *testing.T) {
	d := NewThrottleDetector(25, time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }
	snap := ContainerSnapshot{ID: "c1", Name: "api", Status: "running", CPULimit: 0.5}
	poll := func(periods, throttled uint64) *Issue {
		now = now.Add(30 * time.Second)
		snap.CPUPeriods += periods
		snap.CPUThrottledPeriods += throttled
		return d.Check(snap)
	}

	if poll(0, 0) != nil { // baseline
		t.Fatal("baseline reported")
	}
	if poll(300, 10) != nil {
		t.Fatal("3% throttled reported")
	}
	poll(300, 200)
	poll(300, 200)
	issue := poll(300, 200)
	if issue == nil {
		t.Fatal("expected an alert after a minute at 67%")
	}
	if !strings.Contains(issue.Message, "CPU throttled in 67% of scheduling periods at a limit of 0.5 CPUs") {
		t.Errorf("message = %q", issue.Message)
	}
	// Idle (no periods ran): no new evidence, the episode stays.
	if poll(0, 0) == nil {
		t.Fatal("an idle poll ended the episode")
	}
	// Restart resets the counters: no bogus ratio, and below threshold.
	snap.CPUPeriods, snap.CPUThrottledPeriods = 10, 0
	d.Check(snap)
	if poll(300, 0) != nil {
		t.Fatal("episode should be over")
	}
	// Stopped: state dropped.
	d.Check(ContainerSnapshot{ID: "c1", Status: "exited"})
	if len(d.state) != 0 {
		t.Fatal("state kept for a stopped container")
	}
}
