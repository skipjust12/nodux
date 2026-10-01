package detector

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiskDetector(t *testing.T) {
	usage := map[string]DiskUsage{
		"/":     {Used: 91 << 30, Avail: 9 << 30, InodesUsed: 10, InodesTotal: 100},
		"/data": {Used: 10 << 30, Avail: 90 << 30, InodesUsed: 97, InodesTotal: 100},
		"/btr":  {Used: 1 << 30, Avail: 99 << 30},
	}
	d := NewDiskDetector([]string{"/", "/data", "/btr", "/missing"}, 90)
	d.statfs = func(p string) (DiskUsage, error) {
		u, ok := usage[p]
		if !ok {
			return DiskUsage{}, errors.New("no such file or directory")
		}
		return u, nil
	}

	issues := d.Check()
	if len(issues) != 2 {
		t.Fatalf("got %d issues, want 2: %+v", len(issues), issues)
	}
	if issues[0].Resource != "/" || !strings.Contains(issues[0].Message, "disk / at 91% (91.0GiB used, 9.0GiB free)") {
		t.Errorf("space issue: %+v", issues[0])
	}
	if issues[1].Resource != "/data" || !strings.Contains(issues[1].Message, "inodes on /data at 97%") {
		t.Errorf("inode issue: %+v", issues[1])
	}

	// Hysteresis: 88% keeps it open, 80% closes it.
	usage["/"] = DiskUsage{Used: 88 << 30, Avail: 12 << 30}
	if len(d.Check()) != 2 {
		t.Fatal("episode ended inside the hysteresis band")
	}
	usage["/"] = DiskUsage{Used: 80 << 30, Avail: 20 << 30}
	if issues := d.Check(); len(issues) != 1 || issues[0].Resource != "/data" {
		t.Fatalf("expected only /data left: %+v", issues)
	}
}

func writeProc(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostMemoryDetector(t *testing.T) {
	proc := t.TempDir()
	d := NewHostMemoryDetector(proc, 90, time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }

	if d.Check() != nil {
		t.Fatal("missing meminfo should not produce an issue")
	}

	writeProc(t, proc, "meminfo", "MemTotal:       8000000 kB\nMemFree:  100000 kB\nMemAvailable:    400000 kB\n")
	if d.Check() != nil {
		t.Fatal("alert before the sustain period")
	}
	now = now.Add(time.Minute)
	issues := d.Check()
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "host memory at 95%") || issues[0].Resource != "memory" {
		t.Fatalf("unexpected issues: %+v", issues)
	}
}

func TestCPUDetector(t *testing.T) {
	proc := t.TempDir()
	d := NewCPUDetector(proc, 90, 0)
	stat := func(busy, idle uint64) {
		// user nice system idle iowait irq softirq steal guest guest_nice
		writeProc(t, proc, "stat", "cpu  "+itoa(busy)+" 0 0 "+itoa(idle)+" 0 0 0 0 50 0\ncpu0 1 2 3 4\n")
	}

	stat(100, 100)
	if d.Check() != nil {
		t.Fatal("first sample has nothing to compare against")
	}
	stat(195, 105) // 95 busy of 100
	issues := d.Check()
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "host CPU busy at 95%") {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	stat(195, 105) // counters didn't move: keep the current state
	if len(d.Check()) != 1 {
		t.Fatal("no new data shouldn't end the episode")
	}
	stat(205, 195) // 10 of 100
	if d.Check() != nil {
		t.Fatal("episode should be over")
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func TestExpectedDetector(t *testing.T) {
	d := NewExpectedDetector([]string{"db", "api", "worker"}, time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }

	statuses := map[string]string{"db": "running", "api": "exited", "cron": "exited"}
	if issues := d.Check(statuses, nil); len(issues) != 0 {
		t.Fatalf("reported within the grace period: %+v", issues)
	}
	now = now.Add(time.Minute)
	issues := d.Check(statuses, nil)
	if len(issues) != 2 {
		t.Fatalf("got %+v", issues)
	}
	if issues[0].Container.Name != "api" || !strings.Contains(issues[0].Message, "not running (status: exited)") {
		t.Errorf("api: %+v", issues[0])
	}
	if issues[1].Container.Name != "worker" || !strings.Contains(issues[1].Message, "does not exist") {
		t.Errorf("worker: %+v", issues[1])
	}

	// Recreated by compose: briefly missing, back within grace.
	statuses = map[string]string{"db": "restarting", "api": "running", "worker": "running"}
	if issues := d.Check(statuses, nil); len(issues) != 0 {
		t.Fatalf("got %+v", issues)
	}
	delete(statuses, "db")
	now = now.Add(30 * time.Second)
	if issues := d.Check(statuses, nil); len(issues) != 0 {
		t.Fatalf("db reported within grace: %+v", issues)
	}
}
