package detector

import (
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time                { return c.t }
func (c *clock) add(d time.Duration) time.Time { c.t = c.t.Add(d); return c.t }

func at(id, action string, t time.Time) ContainerEvent {
	return ContainerEvent{ID: id, Name: "flaky", Action: action, Time: t}
}

// crash feeds one crash-and-restart cycle, the way a restart policy
// produces it: a bare die, then start.
func crash(d *CrashLoopDetector, c *clock, id string) *Issue {
	die := at(id, "die", c.add(time.Second))
	die.ExitCode = 3
	d.HandleEvent(die)
	return d.HandleEvent(at(id, "start", c.add(time.Second)))
}

func newCrashLoop(threshold int, window time.Duration) (*CrashLoopDetector, *clock) {
	c := &clock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	d := NewCrashLoopDetector(threshold, window)
	d.now = c.now
	return d, c
}

func TestCrashLoop_FiresOnThresholdFromEvents(t *testing.T) {
	d, c := newCrashLoop(3, 5*time.Minute)
	d.HandleEvent(at("c1", "start", c.t)) // initial docker run: not a restart

	if crash(d, c, "c1") != nil || crash(d, c, "c1") != nil {
		t.Fatal("fired before the threshold")
	}
	issue := crash(d, c, "c1")
	if issue == nil {
		t.Fatal("expected an issue on the third restart")
	}
	if issue.Severity != SeverityCritical || !strings.Contains(issue.Message, "restarted 3 times in the last 5m0s") {
		t.Errorf("unexpected issue: %+v", issue)
	}
	if issue.Container.ID != "c1" || issue.Container.Name != "flaky" || issue.Container.ExitCode != 3 {
		t.Errorf("container not identified: %+v", issue.Container)
	}
	// The episode is open: more restarts don't produce more edges.
	if crash(d, c, "c1") != nil {
		t.Fatal("second edge within one episode")
	}
}

func TestCrashLoop_ManualRestartsDontCount(t *testing.T) {
	d, c := newCrashLoop(2, 5*time.Minute)
	for i := 0; i < 5; i++ {
		// docker restart: stop signal, die, start.
		d.HandleEvent(ContainerEvent{ID: "c1", Action: "kill", Signal: 15, Time: c.add(time.Second)})
		d.HandleEvent(at("c1", "die", c.add(time.Second)))
		if issue := d.HandleEvent(at("c1", "start", c.add(time.Second))); issue != nil {
			t.Fatalf("manual restart counted: %+v", issue)
		}
	}
	// A reload signal before a real crash doesn't hide the crash.
	d.HandleEvent(ContainerEvent{ID: "c1", Action: "kill", Signal: 1, Time: c.add(time.Second)})
	crash(d, c, "c1")
	if crash(d, c, "c1") == nil {
		t.Fatal("crashes after a SIGHUP should count")
	}
}

func TestCrashLoop_OldRestartsExpire(t *testing.T) {
	d, c := newCrashLoop(3, time.Minute)
	crash(d, c, "c1")
	crash(d, c, "c1")
	c.add(2 * time.Minute)
	if issue := crash(d, c, "c1"); issue != nil {
		t.Fatalf("restarts outside the window counted: %+v", issue)
	}
}

func TestCrashLoop_CheckKeepsEpisodeUntilQuietAndRunning(t *testing.T) {
	d, c := newCrashLoop(2, time.Minute)
	crash(d, c, "c1")
	if crash(d, c, "c1") == nil {
		t.Fatal("expected the episode to open")
	}

	snap := ContainerSnapshot{ID: "c1", Name: "flaky", Status: "restarting"}
	if d.Check(snap) == nil {
		t.Fatal("Check should report the open episode")
	}

	// Restart policy gave up: no restarts in the window, but it's dead.
	c.add(2 * time.Minute)
	snap.Status = "exited"
	issue := d.Check(snap)
	if issue == nil || !strings.Contains(issue.Message, "stopped after crash-looping") {
		t.Fatalf("a container that gave up is still broken: %+v", issue)
	}

	// Someone fixed it and it's been up for a whole window.
	snap.Status = "running"
	if issue := d.Check(snap); issue != nil {
		t.Fatalf("episode should be over: %+v", issue)
	}
	if len(d.state) != 0 {
		t.Errorf("state not dropped after the episode: %v", d.state)
	}
}

func TestCrashLoop_CheckIgnoresUnknownAndForgets(t *testing.T) {
	d, c := newCrashLoop(3, 5*time.Minute)
	if d.Check(ContainerSnapshot{ID: "c1", Status: "running"}) != nil {
		t.Fatal("container without restarts reported")
	}
	crash(d, c, "c1")
	d.Forget("c1")
	d.HandleEvent(at("c2", "die", c.t))
	d.HandleEvent(at("c2", "destroy", c.t))
	if len(d.state) != 0 || len(d.crashed) != 0 || len(d.stops) != 0 {
		t.Fatalf("state not dropped: %v %v %v", d.state, d.crashed, d.stops)
	}
}
