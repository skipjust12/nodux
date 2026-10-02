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
	"sync"
	"time"
)

// HostOOMDetector reports OOM kills that no container accounts for: the
// global OOM killer taking out something on the host (sshd, a database
// installed from packages, dockerd itself), or a non-Docker cgroup such
// as a systemd unit with MemoryMax= hitting its limit.
//
// The kernel counts every OOM kill in /proc/vmstat's oom_kill, container
// ones included. Each container kill also produces a Docker "oom" event,
// fed in through ContainerOOM; a kill the counter shows that no event
// claims within the settle window is a host OOM. The two sides are
// matched by count, oldest first, so it doesn't matter which one shows
// up first. While the event stream is down, container OOMs can't be told
// apart and may be reported here.
//
// The alert is one-off, at most one per cooldown, carrying every kill
// since the last one, so a box that keeps OOMing doesn't page every poll
// and no kill goes uncounted.
type HostOOMDetector struct {
	path     string
	settle   time.Duration
	cooldown time.Duration
	now      func() time.Time

	mu      sync.Mutex
	credits []time.Time // container OOM events not matched to a kill yet

	// Only touched by Check (the poll loop).
	prev      uint64
	havePrev  bool
	disabled  bool
	failing   bool
	pending   []oomBatch // kills not matched to a container event yet
	confirmed int        // host OOM kills not reported yet
	lastAlert time.Time
}

type oomBatch struct {
	Kills int       `json:"kills"`
	Seen  time.Time `json:"seen"`
}

func NewHostOOMDetector(procPath string, settle, cooldown time.Duration) *HostOOMDetector {
	return &HostOOMDetector{
		path:     filepath.Join(procPath, "vmstat"),
		settle:   settle,
		cooldown: cooldown,
		now:      time.Now,
	}
}

func (d *HostOOMDetector) Name() string { return "host_oom" }

// ContainerOOM records a container OOM event. Called from the event
// loop for every container, excluded ones included.
func (d *HostOOMDetector) ContainerOOM() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.credits = append(d.credits, d.now())
}

// Check reads the counter and returns an alert once unexplained kills
// have settled, nil otherwise.
func (d *HostOOMDetector) Check() *Issue {
	if d.disabled {
		return nil
	}
	n, err := readVmstat(d.path, "oom_kill")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNoCounter) {
			slog.Warn("host OOM detection not available (needs /proc/vmstat with oom_kill, Linux 4.13+)", "error", err)
			d.disabled = true
			return nil
		}
		if !d.failing {
			slog.Warn("host OOM check failed", "error", err)
			d.failing = true
		}
		return nil
	}
	d.failing = false

	now := d.now()
	if d.havePrev && n > d.prev {
		d.pending = append(d.pending, oomBatch{Kills: int(n - d.prev), Seen: now})
	}
	d.prev, d.havePrev = n, true

	d.mu.Lock()
	// Match container events against kills, oldest first.
	for len(d.credits) > 0 && len(d.pending) > 0 {
		d.credits = d.credits[1:]
		d.pending[0].Kills--
		if d.pending[0].Kills == 0 {
			d.pending = d.pending[1:]
		}
	}
	// An event without a kill (e.g. an OOM condition that the kernel
	// resolved without killing) mustn't hide a later host OOM.
	for len(d.credits) > 0 && now.Sub(d.credits[0]) >= d.settle {
		d.credits = d.credits[1:]
	}
	d.mu.Unlock()

	for len(d.pending) > 0 && now.Sub(d.pending[0].Seen) >= d.settle {
		d.confirmed += d.pending[0].Kills
		d.pending = d.pending[1:]
	}
	if d.confirmed == 0 || (!d.lastAlert.IsZero() && now.Sub(d.lastAlert) < d.cooldown) {
		return nil
	}

	msg := "the kernel OOM killer killed a process outside any container"
	if d.confirmed > 1 {
		msg = fmt.Sprintf("the kernel OOM killer killed %d processes outside any container", d.confirmed)
	}
	if !d.lastAlert.IsZero() {
		msg += fmt.Sprintf(" since %s", d.lastAlert.UTC().Format("15:04 MST"))
	}
	msg += " (host memory ran out, or a non-Docker cgroup hit its limit); check the kernel log: journalctl -k | grep -i oom"
	d.confirmed = 0
	d.lastAlert = now
	return &Issue{
		Detector:   d.Name(),
		Severity:   SeverityCritical,
		Message:    msg,
		Resource:   "oom_kill",
		DetectedAt: now,
	}
}

// readVmstat returns one counter from /proc/vmstat.
func readVmstat(path, key string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, value, ok := strings.Cut(sc.Text(), " ")
		if !ok || name != key {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: bad %s value %q", path, key, value)
		}
		return n, nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s: %w %s", path, errNoCounter, key)
}

var errNoCounter = errors.New("no counter named")

type hostOOMSaved struct {
	Counter   uint64     `json:"counter"`
	Pending   []oomBatch `json:"pending,omitempty"`
	Confirmed int        `json:"confirmed,omitempty"`
	LastAlert time.Time  `json:"last_alert,omitempty"`
}

// SaveState keeps the counter, so kills while nodux was down are still
// counted (container OOMs from that time come back with the replayed
// events), along with the kills not reported yet and the cooldown.
func (d *HostOOMDetector) SaveState() ([]byte, error) {
	if !d.havePrev {
		return json.Marshal(nil)
	}
	return json.Marshal(hostOOMSaved{Counter: d.prev, Pending: d.pending, Confirmed: d.confirmed, LastAlert: d.lastAlert})
}

func (d *HostOOMDetector) LoadState(data []byte) error {
	var sv *hostOOMSaved
	if err := json.Unmarshal(data, &sv); err != nil || sv == nil {
		return err
	}
	// After a reboot the counter starts over below the saved value;
	// Check then just takes a new baseline.
	d.prev, d.havePrev = sv.Counter, true
	d.pending, d.confirmed, d.lastAlert = sv.Pending, sv.Confirmed, sv.LastAlert
	return nil
}
