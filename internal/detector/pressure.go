package detector

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PressureRule is one PSI signal to watch: a resource (cpu, memory, io),
// a line (some, full) and the avg60 percentage that's too much.
type PressureRule struct {
	Resource  string
	Kind      string
	Threshold float64
}

// PressureDetector watches pressure stall information from
// /proc/pressure/{cpu,memory,io}: the share of wall time in which some
// (or all) non-idle tasks were stalled waiting for a resource, averaged
// over the last 60 seconds. Unlike utilization, it measures the damage
// directly:
//
//   - memory some: tasks are waiting on reclaim, swap-in or refaults.
//     The box is thrashing, typically well before the OOM killer runs.
//   - io full: every runnable task is waiting on I/O at once. A dying
//     disk, or a noisy neighbour on the same storage.
//   - cpu some: runnable tasks are waiting for a CPU.
//
// Each rule is a separate episode, with the usual sustain period and
// hysteresis. PSI needs Linux 4.20+ built with CONFIG_PSI (some distro
// kernels need psi=1 on the command line); without it the detector logs
// once and stays quiet.
type PressureDetector struct {
	procPath string
	rules    []PressureRule
	gates    []*gate
	sustain  time.Duration
	failing  map[string]bool // resources whose file can't be read, logged once
	now      func() time.Time
}

func NewPressureDetector(procPath string, rules []PressureRule, sustain time.Duration) *PressureDetector {
	d := &PressureDetector{
		procPath: procPath,
		rules:    rules,
		sustain:  sustain,
		failing:  make(map[string]bool),
		now:      time.Now,
	}
	for _, r := range rules {
		d.gates = append(d.gates, &gate{threshold: r.Threshold, sustain: sustain})
	}
	return d
}

func (d *PressureDetector) Name() string { return "host_pressure" }

func (d *PressureDetector) Check() []*Issue {
	files := make(map[string]map[string]float64) // resource -> kind -> avg60
	var issues []*Issue
	for i, r := range d.rules {
		avgs, ok := files[r.Resource]
		if !ok {
			avgs = d.read(r.Resource)
			files[r.Resource] = avgs
		}
		avg, ok := avgs[r.Kind]
		if !ok {
			continue
		}
		g := d.gates[i]
		if !g.update(d.now(), avg) {
			continue
		}
		issues = append(issues, &Issue{
			Detector:   d.Name(),
			Severity:   SeverityWarning,
			Message:    pressureMessage(r, avg, d.sustain),
			Resource:   r.Resource + "_" + r.Kind,
			DetectedAt: d.now(),
		})
	}
	return issues
}

// read returns the avg60 values of one /proc/pressure file, nil if it
// can't be read.
func (d *PressureDetector) read(resource string) map[string]float64 {
	path := filepath.Join(d.procPath, "pressure", resource)
	avgs, err := readPressure(path)
	if err != nil {
		if !d.failing[resource] {
			if errors.Is(err, fs.ErrNotExist) {
				slog.Warn("pressure stall information not available (needs Linux 4.20+ with CONFIG_PSI, or psi=1 on the kernel command line)", "path", path)
			} else {
				slog.Warn("pressure check failed", "path", path, "error", err)
			}
			d.failing[resource] = true
		}
		return nil
	}
	delete(d.failing, resource)
	return avgs
}

// readPressure parses lines like
//
//	some avg10=0.00 avg60=1.25 avg300=0.40 total=12345
//
// into {"some": 1.25, ...}.
func readPressure(path string) (map[string]float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]float64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		for _, kv := range fields[1:] {
			v, ok := strings.CutPrefix(kv, "avg60=")
			if !ok {
				continue
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("%s: bad avg60 %q", path, v)
			}
			out[fields[0]] = n
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no avg60 values", path)
	}
	return out, nil
}

func pressureMessage(r PressureRule, avg float64, sustain time.Duration) string {
	msg := fmt.Sprintf("%s pressure: %s avg60 at %.1f%% (threshold %g%%)", r.Resource, r.Kind, avg, r.Threshold)
	if sustain > 0 {
		msg += fmt.Sprintf(" for at least %s", sustain)
	}
	if hint := pressureHints[r.Resource+"_"+r.Kind]; hint != "" {
		msg += ": " + hint
	}
	return msg
}

var pressureHints = map[string]string{
	"memory_some": "tasks are stalling on reclaim and swap-in, the system is thrashing",
	"memory_full": "every task is stalled on memory, the system is thrashing hard",
	"io_some":     "tasks are waiting on I/O",
	"io_full":     "every task is waiting on I/O at once: a slow or failing disk, or a noisy neighbour on shared storage",
	"cpu_some":    "runnable tasks are waiting for a CPU",
	"cpu_full":    "every task is waiting for a CPU",
}

// SaveState keeps which signals are firing, so a restart doesn't
// resolve them while they sit in the hysteresis gap.
func (d *PressureDetector) SaveState() ([]byte, error) {
	var firing []string
	for i, r := range d.rules {
		if d.gates[i].firing {
			firing = append(firing, r.Resource+"_"+r.Kind)
		}
	}
	return json.Marshal(firing)
}

func (d *PressureDetector) LoadState(data []byte) error {
	var firing []string
	if err := json.Unmarshal(data, &firing); err != nil {
		return err
	}
	for _, key := range firing {
		for i, r := range d.rules {
			if r.Resource+"_"+r.Kind == key {
				d.gates[i].firing = true
			}
		}
	}
	return nil
}
