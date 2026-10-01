package detector

import (
	"strings"
	"testing"
	"time"
)

func TestHostOOMDetector(t *testing.T) {
	proc := t.TempDir()
	d := NewHostOOMDetector(proc, 30*time.Second, 10*time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }
	vmstat := func(n string) { writeProc(t, proc, "vmstat", "nr_free_pages 123\noom_kill "+n+"\npgfault 9\n") }
	poll := func(after time.Duration) *Issue {
		now = now.Add(after)
		return d.Check()
	}

	vmstat("7") // baseline: kills before nodux started don't count
	if poll(0) != nil {
		t.Fatal("baseline reported")
	}

	// A container OOM: the event usually arrives before the poll sees
	// the counter move.
	d.ContainerOOM()
	vmstat("8")
	if poll(15*time.Second) != nil || poll(30*time.Second) != nil {
		t.Fatal("container OOM reported as a host OOM")
	}

	// The event can also arrive after the counter moved.
	vmstat("9")
	if poll(15*time.Second) != nil {
		t.Fatal("reported before the settle window")
	}
	d.ContainerOOM()
	if poll(30*time.Second) != nil {
		t.Fatal("late container event not matched")
	}

	// Two kills nobody claims: one alert once they've settled.
	vmstat("11")
	if poll(15*time.Second) != nil {
		t.Fatal("reported before the settle window")
	}
	issue := poll(30 * time.Second)
	if issue == nil || issue.Severity != SeverityCritical || !strings.Contains(issue.Message, "killed 2 processes outside any container") {
		t.Fatalf("unexpected issue: %+v", issue)
	}

	// More kills within the cooldown are held and counted, not lost.
	vmstat("12")
	poll(15 * time.Second)
	if poll(time.Minute) != nil {
		t.Fatal("alert within the cooldown")
	}
	vmstat("13")
	poll(15 * time.Second)
	if poll(time.Minute) != nil {
		t.Fatal("alert within the cooldown")
	}
	issue = poll(10 * time.Minute)
	if issue == nil || !strings.Contains(issue.Message, "killed 2 processes") || !strings.Contains(issue.Message, " since ") {
		t.Fatalf("held kills not reported after the cooldown: %+v", issue)
	}

	// A stray container event that never matches a kill expires, so it
	// can't hide a later host OOM.
	d.ContainerOOM()
	poll(time.Minute)
	vmstat("14")
	poll(15 * time.Minute)
	if issue := poll(time.Minute); issue == nil || !strings.Contains(issue.Message, "killed a process outside") {
		t.Fatalf("stray event hid a host OOM: %+v", issue)
	}
}

func TestHostOOMDetector_NoCounter(t *testing.T) {
	proc := t.TempDir()
	d := NewHostOOMDetector(proc, time.Second, 0)
	writeProc(t, proc, "vmstat", "nr_free_pages 1\n")
	if d.Check() != nil || !d.disabled {
		t.Fatal("expected the detector to switch itself off")
	}
}
