package detector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writePressure(t *testing.T, proc, resource string, some, full float64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(proc, "pressure"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "some avg10=99.00 avg60=" + ftoa(some) + " avg300=0.00 total=123\n" +
		"full avg10=99.00 avg60=" + ftoa(full) + " avg300=0.00 total=45\n"
	writeProc(t, filepath.Join(proc, "pressure"), resource, body)
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

func TestPressureDetector(t *testing.T) {
	proc := t.TempDir()
	d := NewPressureDetector(proc, []PressureRule{
		{Resource: "memory", Kind: "some", Threshold: 10},
		{Resource: "io", Kind: "full", Threshold: 4},
	}, time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }

	// No PSI on this kernel: quiet, no crash.
	if issues := d.Check(); issues != nil {
		t.Fatalf("issues without PSI: %+v", issues)
	}

	// avg10 is 99 everywhere: only avg60 matters.
	writePressure(t, proc, "memory", 23.5, 0)
	writePressure(t, proc, "io", 1, 5)
	if issues := d.Check(); issues != nil {
		t.Fatalf("alert before the sustain period: %+v", issues)
	}
	now = now.Add(time.Minute)
	issues := d.Check()
	if len(issues) != 2 {
		t.Fatalf("got %+v", issues)
	}
	if issues[0].Resource != "memory_some" || !strings.Contains(issues[0].Message, "memory pressure: some avg60 at 23.5% (threshold 10%)") ||
		!strings.Contains(issues[0].Message, "thrashing") {
		t.Errorf("memory: %+v", issues[0])
	}
	if issues[1].Resource != "io_full" || !strings.Contains(issues[1].Message, "io pressure: full avg60 at 5.0%") {
		t.Errorf("io: %+v", issues[1])
	}

	// A threshold of 4 rearms below 2, not below -1 (it would never close).
	writePressure(t, proc, "io", 1, 2.5)
	if issues := d.Check(); len(issues) != 2 {
		t.Fatalf("io closed inside the hysteresis band: %+v", issues)
	}
	writePressure(t, proc, "io", 1, 1.5)
	if issues := d.Check(); len(issues) != 1 || issues[0].Resource != "memory_some" {
		t.Fatalf("io should be over: %+v", issues)
	}
}

func TestReadPressure_CPUWithoutFullLine(t *testing.T) {
	dir := t.TempDir()
	writeProc(t, dir, "cpu", "some avg10=1.00 avg60=2.50 avg300=3.00 total=10\n")
	got, err := readPressure(filepath.Join(dir, "cpu"))
	if err != nil || got["some"] != 2.5 || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	writeProc(t, dir, "bad", "garbage\n")
	if _, err := readPressure(filepath.Join(dir, "bad")); err == nil {
		t.Fatal("expected an error for a file without avg60")
	}
}
