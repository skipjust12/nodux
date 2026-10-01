package detector

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLabels_Parsing(t *testing.T) {
	labels := map[string]string{
		"nodux.enable":               "false",
		"nodux.expected":             "TRUE",
		"nodux.exit.enable":          "false",
		"nodux.memory.threshold":     "80%",
		"nodux.memory.for":           "120",
		"nodux.crashloop.window":     "10m",
		"nodux.crashloop.threshold":  "zero",
		"nodux.exit.ignore":          "0, 143",
		"com.docker.compose.project": "shop",
		"maintainer":                 "someone",
	}
	if !Excluded(labels) || !ExpectedByLabel(labels) {
		t.Error("enable/expected not parsed")
	}
	if Enabled(labels, "exit") || !Enabled(labels, "oom") {
		t.Error("per-detector enable not parsed")
	}
	if v, ok := labelPercent(labels, "nodux.memory.threshold"); !ok || v != 80 {
		t.Errorf("threshold = %v, %v", v, ok)
	}
	if d, ok := labelDuration(labels, "nodux.memory.for"); !ok || d != 2*time.Minute {
		t.Errorf("for = %v, %v", d, ok)
	}
	if d, ok := labelDuration(labels, "nodux.crashloop.window"); !ok || d != 10*time.Minute {
		t.Errorf("window = %v, %v", d, ok)
	}
	if _, ok := labelPositiveInt(labels, "nodux.crashloop.threshold"); ok {
		t.Error("invalid value accepted")
	}
	if codes, ok := labelInts(labels, "nodux.exit.ignore"); !ok || !reflect.DeepEqual(codes, []int{0, 143}) {
		t.Errorf("ignore = %v, %v", codes, ok)
	}
	if Excluded(nil) || !Enabled(nil, "exit") || ExpectedByLabel(map[string]string{"nodux.expected": "maybe"}) {
		t.Error("missing or invalid labels must fall back to the defaults")
	}

	rel := RelevantLabels(map[string]string{"name": "api", "image": "x", "exitCode": "1", "nodux.enable": "true", "com.docker.compose.service": "api"})
	if !reflect.DeepEqual(rel, map[string]string{"nodux.enable": "true", "com.docker.compose.service": "api"}) {
		t.Errorf("relevant labels = %v", rel)
	}
}

func TestMemoryDetector_LabelOverrides(t *testing.T) {
	d := NewMemoryDetector(90, time.Hour)
	s := memSnap(85)
	s.Labels = map[string]string{"nodux.memory.threshold": "80", "nodux.memory.for": "0"}
	issue := d.Check(s)
	if issue == nil || strings.Contains(issue.Message, "for at least") {
		t.Fatalf("label threshold/for not applied: %+v", issue)
	}
}

func TestCrashLoop_LabelOverrides(t *testing.T) {
	d, c := newCrashLoop(5, time.Minute)
	labeled := func(ev ContainerEvent) ContainerEvent {
		ev.Labels = map[string]string{"nodux.crashloop.threshold": "2", "nodux.crashloop.window": "10m"}
		return ev
	}
	for i := 0; i < 2; i++ {
		d.HandleEvent(labeled(at("c1", "die", c.add(time.Minute))))
		issue := d.HandleEvent(labeled(at("c1", "start", c.add(time.Minute))))
		if i == 1 && (issue == nil || !strings.Contains(issue.Message, "2 times in the last 10m0s")) {
			t.Fatalf("label threshold/window not applied: %+v", issue)
		}
	}
}

func TestExitDetector_IgnoreLabel(t *testing.T) {
	d := NewExitDetector([]int{0}, true)
	die := ContainerEvent{ID: "j1", Name: "job", Action: "die", ExitCode: 3, Labels: map[string]string{"nodux.exit.ignore": "0,3"}}
	if d.HandleEvent(die) != nil {
		t.Fatal("exit code listed in nodux.exit.ignore was reported")
	}
	die.ExitCode = 1
	if d.HandleEvent(die) == nil {
		t.Fatal("other exit codes must still be reported")
	}
}

func TestExpectedDetector_Labeled(t *testing.T) {
	d := NewExpectedDetector(nil, 0)
	issues := d.Check(map[string]string{"api": "exited"}, []string{"api"})
	if len(issues) != 1 || issues[0].Container.Name != "api" {
		t.Fatalf("labeled container not expected: %+v", issues)
	}
	// Removed together with its label: no longer expected.
	if issues := d.Check(map[string]string{}, nil); len(issues) != 0 {
		t.Fatalf("removed labeled container reported: %+v", issues)
	}
}

// roundTrip saves a detector's state and loads it into a fresh one.
func roundTrip(t *testing.T, from, to Stateful) {
	t.Helper()
	data, err := from.SaveState()
	if err != nil {
		t.Fatal(err)
	}
	if err := to.LoadState(data); err != nil {
		t.Fatal(err)
	}
}

func TestState_CrashLoopSurvivesRestart(t *testing.T) {
	d, c := newCrashLoop(3, 5*time.Minute)
	crash(d, c, "c1")
	crash(d, c, "c1")
	// A die seen before the restart, its start after it.
	die := at("c1", "die", c.add(time.Second))
	die.ExitCode = 7
	d.HandleEvent(die)

	d2, _ := newCrashLoop(3, 5*time.Minute)
	d2.now = c.now
	roundTrip(t, d, d2)
	issue := d2.HandleEvent(at("c1", "start", c.add(time.Second)))
	if issue == nil || issue.Container.ExitCode != 7 {
		t.Fatalf("restarts counted before the restart were lost: %+v", issue)
	}
	if d2.Check(ContainerSnapshot{ID: "c1", Status: "restarting"}) == nil {
		t.Fatal("episode not kept open after restore")
	}
}

func TestState_FiringGatesSurviveRestart(t *testing.T) {
	m := NewMemoryDetector(90, 0)
	if m.Check(memSnap(95)) == nil {
		t.Fatal("setup: no alert")
	}
	m2 := NewMemoryDetector(90, time.Hour)
	roundTrip(t, m, m2)
	// 87% is inside the hysteresis band: a fresh gate would say "fine".
	if m2.Check(memSnap(87)) == nil {
		t.Fatal("firing memory gate lost on restore")
	}

	disk := NewDiskDetector([]string{"/", "/data"}, 90)
	disk.gates["/data"].firing = true
	disk2 := NewDiskDetector([]string{"/", "/data"}, 90)
	roundTrip(t, disk, disk2)
	if !disk2.gates["/data"].firing || disk2.gates["/"].firing {
		t.Fatalf("disk gates: %+v %+v", disk2.gates["/"], disk2.gates["/data"])
	}

	cpu := NewCPUDetector("/proc", 95, 0)
	cpu.gate.firing, cpu.lastPct = true, 99
	cpu2 := NewCPUDetector("/proc", 95, 0)
	roundTrip(t, cpu, cpu2)
	if !cpu2.gate.firing || cpu2.lastPct != 99 {
		t.Fatal("cpu gate lost")
	}

	hm := NewHostMemoryDetector("/proc", 90, 0)
	hm.gate.firing = true
	hm2 := NewHostMemoryDetector("/proc", 90, 0)
	roundTrip(t, hm, hm2)
	if !hm2.gate.firing {
		t.Fatal("host memory gate lost")
	}
}

func TestState_ExitAndExpected(t *testing.T) {
	e := NewExitDetector([]int{0}, true)
	e.HandleEvent(ContainerEvent{ID: "w1", Action: "kill", Signal: 15})
	e2 := NewExitDetector([]int{0}, true)
	roundTrip(t, e, e2)
	if e2.HandleEvent(ContainerEvent{ID: "w1", Action: "die", ExitCode: 143}) != nil {
		t.Fatal("a stop requested before the restart was reported as a crash after it")
	}

	x := NewExpectedDetector([]string{"db"}, time.Minute)
	now := time.Now()
	x.now = func() time.Time { return now }
	x.Check(map[string]string{}, nil)
	x2 := NewExpectedDetector([]string{"db"}, time.Minute)
	x2.now = func() time.Time { return now.Add(time.Minute) }
	roundTrip(t, x, x2)
	if issues := x2.Check(map[string]string{}, nil); len(issues) != 1 {
		t.Fatalf("grace period restarted after restore: %+v", issues)
	}
}
