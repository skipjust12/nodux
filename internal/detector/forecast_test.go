package detector

import (
	"strings"
	"testing"
	"time"
)

func TestDiskForecastDetector(t *testing.T) {
	const gib = 1 << 30
	d := NewDiskForecastDetector([]string{"/"}, time.Hour, 12*time.Hour)
	now := time.Now()
	d.now = func() time.Time { return now }
	avail := uint64(10 * gib)
	d.statfs = func(string) (DiskUsage, error) { return DiskUsage{Used: 10 * gib, Avail: avail}, nil }

	// Losing 1 GiB/h with 10 GiB free: ~10h to full, but nothing is said
	// until a quarter of the window is covered.
	step := func() []*Issue {
		now = now.Add(5 * time.Minute)
		avail -= gib / 12
		return d.Check()
	}
	d.Check()
	for i := 0; i < 2; i++ {
		if issues := step(); issues != nil {
			t.Fatalf("forecast from too little data: %+v", issues)
		}
	}
	issues := step()
	if len(issues) != 1 || issues[0].Resource != "/" {
		t.Fatalf("got %+v", issues)
	}
	if msg := issues[0].Message; !strings.Contains(msg, "disk / will be full in ~10h") || !strings.Contains(msg, "filling at 1.0GiB/h") {
		t.Errorf("message = %q", msg)
	}

	// Slowing down to ~16h to full stays inside 2x the horizon...
	for i := 0; i < 12; i++ {
		now = now.Add(5 * time.Minute)
		avail -= gib / 30
		if d.Check() == nil && i < 3 {
			t.Fatal("episode closed inside the hysteresis band")
		}
	}
	// ...and a cleanup ends it.
	avail = 15 * gib
	for i := 0; i < 12; i++ {
		now = now.Add(5 * time.Minute)
		d.Check()
	}
	if issues := d.Check(); issues != nil {
		t.Fatalf("episode should be over after a cleanup: %+v", issues)
	}
}

func TestDiskForecastDetector_FlatDiskNeverFires(t *testing.T) {
	d := NewDiskForecastDetector([]string{"/"}, time.Hour, 12*time.Hour)
	now := time.Now()
	d.now = func() time.Time { return now }
	d.statfs = func(string) (DiskUsage, error) { return DiskUsage{Used: 99, Avail: 1}, nil }
	for i := 0; i < 20; i++ {
		now = now.Add(5 * time.Minute)
		if issues := d.Check(); issues != nil {
			t.Fatalf("flat usage forecast to fill: %+v", issues)
		}
	}
}

func TestFormatETA(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second: "1m", 40 * time.Minute: "40m", 6*time.Hour + 20*time.Minute: "6h", 72 * time.Hour: "3d",
	} {
		if got := FormatETA(d); got != want {
			t.Errorf("FormatETA(%s) = %q, want %q", d, got, want)
		}
	}
}
