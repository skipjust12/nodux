package detector

import (
	"testing"
	"time"
)

// Each detector that can hold an episode open keeps it open across a
// save/load, instead of resolving it and firing again later.

func TestPressureDetector_State(t *testing.T) {
	proc := t.TempDir()
	rules := []PressureRule{{Resource: "io", Kind: "full", Threshold: 10}}
	d := NewPressureDetector(proc, rules, 0)
	writePressure(t, proc, "io", 0, 50)
	if len(d.Check()) != 1 {
		t.Fatal("expected an issue")
	}
	saved, err := d.SaveState()
	if err != nil {
		t.Fatal(err)
	}
	d2 := NewPressureDetector(proc, rules, time.Hour) // the sustain period would hold a fresh one back
	if err := d2.LoadState(saved); err != nil {
		t.Fatal(err)
	}
	writePressure(t, proc, "io", 0, 8) // inside the hysteresis band
	if len(d2.Check()) != 1 {
		t.Fatal("restored episode closed inside the hysteresis band")
	}
}

func TestThrottleDetector_State(t *testing.T) {
	d := NewThrottleDetector(25, 0)
	snap := ContainerSnapshot{ID: "c1", Status: "running", CPULimit: 1}
	d.Check(snap)
	snap.CPUPeriods, snap.CPUThrottledPeriods = 100, 90
	if d.Check(snap) == nil {
		t.Fatal("expected an issue")
	}
	saved, _ := d.SaveState()
	d2 := NewThrottleDetector(25, time.Hour)
	if err := d2.LoadState(saved); err != nil {
		t.Fatal(err)
	}
	// Counters after a restart of nodux: the first sample is a baseline,
	// and the episode stays open.
	snap.CPUPeriods, snap.CPUThrottledPeriods = 500, 450
	if issue := d2.Check(snap); issue == nil {
		t.Fatal("restored episode closed on the baseline sample")
	}
	snap.CPUPeriods, snap.CPUThrottledPeriods = 600, 451
	if d2.Check(snap) != nil {
		t.Fatal("episode should end once throttling stops")
	}
}

func TestDiskForecastDetector_State(t *testing.T) {
	const gib = 1 << 30
	now := time.Now()
	avail := uint64(10 * gib)
	mk := func() *DiskForecastDetector {
		d := NewDiskForecastDetector([]string{"/"}, time.Hour, 12*time.Hour)
		d.now = func() time.Time { return now }
		d.statfs = func(string) (DiskUsage, error) { return DiskUsage{Avail: avail}, nil }
		return d
	}
	d := mk()
	for i := 0; i < 5; i++ {
		d.Check()
		now = now.Add(5 * time.Minute)
		avail -= gib / 12
	}
	if len(d.Check()) != 1 {
		t.Fatal("expected a forecast")
	}
	saved, _ := d.SaveState()
	d2 := mk()
	if err := d2.LoadState(saved); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if len(d2.Check()) != 1 {
		t.Fatal("restored detector lost its samples")
	}
}

func TestHostOOMDetector_State(t *testing.T) {
	proc := t.TempDir()
	now := time.Now()
	mk := func() *HostOOMDetector {
		d := NewHostOOMDetector(proc, 30*time.Second, 0)
		d.now = func() time.Time { return now }
		return d
	}
	writeProc(t, proc, "vmstat", "oom_kill 5\n")
	d := mk()
	d.Check()
	saved, _ := d.SaveState()

	// A kill while nodux was down still counts.
	writeProc(t, proc, "vmstat", "oom_kill 6\n")
	d2 := mk()
	if err := d2.LoadState(saved); err != nil {
		t.Fatal(err)
	}
	d2.Check()
	now = now.Add(time.Minute)
	if d2.Check() == nil {
		t.Fatal("kill during the downtime not reported")
	}

	// After a reboot the counter starts over: a new baseline, no alert.
	saved, _ = d2.SaveState()
	writeProc(t, proc, "vmstat", "oom_kill 0\n")
	d3 := mk()
	d3.LoadState(saved)
	now = now.Add(time.Minute)
	if d3.Check() != nil || d3.Check() != nil {
		t.Fatal("counter reset reported as kills")
	}
}
