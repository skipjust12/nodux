package detector

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DiskUsage is one filesystem's usage, as statfs reports it.
type DiskUsage struct {
	Used, Avail             uint64 // bytes; Avail is what non-root can still write
	InodesUsed, InodesTotal uint64 // InodesTotal 0 = fs without fixed inodes (btrfs)
}

// DiskDetector fires when a filesystem is at or above threshold percent
// full, by space or by inodes, whichever is worse. Percent is computed
// the way df does: used / (used + available to non-root).
type DiskDetector struct {
	paths     []string
	threshold float64
	gates     map[string]*gate
	failing   map[string]bool // statfs errors already logged, to not spam
	statfs    func(path string) (DiskUsage, error)
	now       func() time.Time
}

func NewDiskDetector(paths []string, thresholdPercent float64) *DiskDetector {
	d := &DiskDetector{
		paths:     paths,
		threshold: thresholdPercent,
		gates:     make(map[string]*gate),
		failing:   make(map[string]bool),
		statfs:    statfs,
		now:       time.Now,
	}
	for _, p := range paths {
		d.gates[p] = &gate{threshold: thresholdPercent}
	}
	return d
}

func (d *DiskDetector) Name() string { return "host_disk" }

func (d *DiskDetector) Check() []*Issue {
	var issues []*Issue
	for _, path := range d.paths {
		u, err := d.statfs(path)
		if err != nil {
			if !d.failing[path] {
				slog.Warn("disk check failed", "path", path, "error", err)
				d.failing[path] = true
			}
			continue
		}
		delete(d.failing, path)

		space := percent(u.Used, u.Used+u.Avail)
		inodes := percent(u.InodesUsed, u.InodesTotal)
		if !d.gates[path].update(d.now(), max(space, inodes)) {
			continue
		}
		msg := fmt.Sprintf("disk %s at %.0f%% (%s used, %s free)", path, space, formatBytes(u.Used), formatBytes(u.Avail))
		if inodes > space {
			msg = fmt.Sprintf("inodes on %s at %.0f%% (%d of %d used)", path, inodes, u.InodesUsed, u.InodesTotal)
		}
		issues = append(issues, &Issue{
			Detector:   d.Name(),
			Severity:   SeverityCritical,
			Message:    msg,
			Resource:   path,
			DetectedAt: d.now(),
		})
	}
	return issues
}

// HostMemoryDetector fires when the host's memory in use (MemTotal -
// MemAvailable, i.e. not counting reclaimable cache) stays at or above
// threshold percent for sustain.
type HostMemoryDetector struct {
	procPath string
	gate     gate
	failing  bool
	now      func() time.Time
}

func NewHostMemoryDetector(procPath string, thresholdPercent float64, sustain time.Duration) *HostMemoryDetector {
	return &HostMemoryDetector{
		procPath: procPath,
		gate:     gate{threshold: thresholdPercent, sustain: sustain},
		now:      time.Now,
	}
}

func (d *HostMemoryDetector) Name() string { return "host_memory" }

func (d *HostMemoryDetector) Check() []*Issue {
	total, avail, err := readMeminfo(filepath.Join(d.procPath, "meminfo"))
	if err != nil {
		if !d.failing {
			slog.Warn("host memory check failed", "error", err)
			d.failing = true
		}
		return nil
	}
	d.failing = false

	used := total - avail
	pct := percent(used, total)
	if !d.gate.update(d.now(), pct) {
		return nil
	}
	msg := fmt.Sprintf("host memory at %.0f%% (%s of %s in use)", pct, formatBytes(used), formatBytes(total))
	if d.gate.sustain > 0 {
		msg += fmt.Sprintf(" for at least %s", d.gate.sustain)
	}
	return []*Issue{{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Resource:   "memory",
		DetectedAt: d.now(),
	}}
}

// readMeminfo returns MemTotal and MemAvailable in bytes.
func readMeminfo(path string) (total, avail uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total, haveTotal = kb*1024, true
		case "MemAvailable:":
			avail, haveAvail = kb*1024, true
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	if !haveTotal || !haveAvail || total == 0 || avail > total {
		return 0, 0, fmt.Errorf("%s: no usable MemTotal/MemAvailable", path)
	}
	return total, avail, nil
}

// CPUDetector fires when the host's CPUs are busy at or above threshold
// percent for sustain, measured between consecutive checks from
// /proc/stat. iowait counts as idle; steal counts as busy (on a VPS, a
// noisy neighbour hurts just the same).
type CPUDetector struct {
	procPath  string
	gate      gate
	prevBusy  uint64
	prevTotal uint64
	lastPct   float64
	failing   bool
	now       func() time.Time
}

func NewCPUDetector(procPath string, thresholdPercent float64, sustain time.Duration) *CPUDetector {
	return &CPUDetector{
		procPath: procPath,
		gate:     gate{threshold: thresholdPercent, sustain: sustain},
		now:      time.Now,
	}
}

func (d *CPUDetector) Name() string { return "host_cpu" }

func (d *CPUDetector) Check() []*Issue {
	busy, total, err := readCPUStat(filepath.Join(d.procPath, "stat"))
	if err != nil {
		if !d.failing {
			slog.Warn("host CPU check failed", "error", err)
			d.failing = true
		}
		return nil
	}
	d.failing = false

	prevBusy, prevTotal := d.prevBusy, d.prevTotal
	d.prevBusy, d.prevTotal = busy, total
	if prevTotal == 0 || total <= prevTotal || busy < prevBusy {
		// First sample, or counters didn't move: nothing to compare.
		// Keep reporting the current state without advancing the gate.
		if d.gate.firing {
			return []*Issue{d.issue(d.lastPct)}
		}
		return nil
	}

	pct := percent(busy-prevBusy, total-prevTotal)
	d.lastPct = pct
	if !d.gate.update(d.now(), pct) {
		return nil
	}
	return []*Issue{d.issue(pct)}
}

func (d *CPUDetector) issue(pct float64) *Issue {
	msg := fmt.Sprintf("host CPU busy at %.0f%%", pct)
	if d.gate.sustain > 0 {
		msg += fmt.Sprintf(" for at least %s", d.gate.sustain)
	}
	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityWarning,
		Message:    msg,
		Resource:   "cpu",
		DetectedAt: d.now(),
	}
}

// readCPUStat returns cumulative busy and total jiffies across all CPUs
// from the "cpu" line of /proc/stat.
func readCPUStat(path string) (busy, total uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		// user nice system idle iowait irq softirq steal [guest guest_nice]
		// guest time is already included in user/nice.
		var v [8]uint64
		for i := 0; i < len(v) && i+1 < len(fields); i++ {
			n, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("%s: bad cpu line: %w", path, err)
			}
			v[i] = n
		}
		for _, n := range v {
			total += n
		}
		idle := v[3] + v[4]
		return total - idle, total, nil
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("%s: no cpu line", path)
}

func percent(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}
