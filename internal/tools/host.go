package tools

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

func (t *Toolbox) diskUsage(ctx context.Context) (string, error) {
	df, err := t.cfg.Docker.DiskUsage(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder

	var imgTotal, unusedSize int64
	var unused, dangling int
	for _, img := range df.Images {
		imgTotal += img.Size
		if img.Containers == 0 {
			unused++
			unusedSize += img.Size - img.SharedSize
		}
		if len(img.RepoTags) == 0 || (len(img.RepoTags) == 1 && img.RepoTags[0] == "<none>:<none>") {
			dangling++
		}
	}
	if df.LayersSize > 0 {
		imgTotal = df.LayersSize // shared layers counted once
	}
	fmt.Fprintf(&b, "images: %d, %s on disk; %d used by no container (about %s not shared with others); %d dangling (untagged)\n",
		len(df.Images), bytesStr(imgTotal), unused, bytesStr(unusedSize), dangling)

	type sized struct {
		name string
		size int64
	}
	var rw int64
	var layers []sized
	for _, c := range df.Containers {
		rw += c.SizeRw
		name := c.ID
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		layers = append(layers, sized{name, c.SizeRw})
	}
	fmt.Fprintf(&b, "containers: %d, writable layers %s%s\n", len(df.Containers), bytesStr(rw), largest(layers, func(s sized) (string, int64) { return s.name, s.size }))

	var volTotal int64
	var vols []sized
	for _, v := range df.Volumes {
		if v.UsageData == nil || v.UsageData.Size < 0 {
			continue
		}
		volTotal += v.UsageData.Size
		vols = append(vols, sized{v.Name, v.UsageData.Size})
	}
	fmt.Fprintf(&b, "volumes: %d, %s%s\n", len(df.Volumes), bytesStr(volTotal), largest(vols, func(s sized) (string, int64) { return s.name, s.size }))

	var cache, reclaimable int64
	for _, bc := range df.BuildCache {
		cache += bc.Size
		if !bc.InUse && !bc.Shared {
			reclaimable += bc.Size
		}
	}
	fmt.Fprintf(&b, "build cache: %s, %s reclaimable\n", bytesStr(cache), bytesStr(reclaimable))
	b.WriteString("Container logs (json-file) aren't included: they live under the Docker data root.\n")
	return b.String(), nil
}

func largest[T any](items []T, get func(T) (string, int64)) string {
	sort.Slice(items, func(i, j int) bool {
		_, a := get(items[i])
		_, b := get(items[j])
		return a > b
	})
	var parts []string
	for i, it := range items {
		name, size := get(it)
		if i == 5 || size <= 0 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", name, bytesStr(size)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "; largest: " + strings.Join(parts, ", ")
}

func (t *Toolbox) hostOverview(ctx context.Context) (string, error) {
	proc := t.cfg.ProcPath
	var b strings.Builder

	if raw, err := os.ReadFile(filepath.Join(proc, "uptime")); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 {
			if secs, err := strconv.ParseFloat(f[0], 64); err == nil {
				fmt.Fprintf(&b, "uptime: %s\n", (time.Duration(secs) * time.Second).Round(time.Minute))
			}
		}
	}
	cpus := countCPUs(filepath.Join(proc, "stat"))
	if raw, err := os.ReadFile(filepath.Join(proc, "loadavg")); err == nil {
		if f := strings.Fields(string(raw)); len(f) >= 3 {
			fmt.Fprintf(&b, "load average: %s %s %s (%d CPUs)\n", f[0], f[1], f[2], cpus)
		}
	}
	if mem, err := readMeminfo(filepath.Join(proc, "meminfo")); err == nil {
		total, avail := mem["MemTotal"], mem["MemAvailable"]
		fmt.Fprintf(&b, "memory: %s of %s in use, %s available", detector.FormatBytes(total-avail), detector.FormatBytes(total), detector.FormatBytes(avail))
		if st := mem["SwapTotal"]; st > 0 {
			fmt.Fprintf(&b, "; swap %s of %s in use", detector.FormatBytes(st-mem["SwapFree"]), detector.FormatBytes(st))
		}
		b.WriteString("\n")
	}
	for _, p := range t.cfg.DiskPaths {
		u, err := detector.Statfs(p)
		if err != nil {
			fmt.Fprintf(&b, "disk %s: %v\n", p, err)
			continue
		}
		total := u.Used + u.Avail
		pct := 0.0
		if total > 0 {
			pct = float64(u.Used) / float64(total) * 100
		}
		fmt.Fprintf(&b, "disk %s: %.0f%% full (%s used, %s free)", p, pct, detector.FormatBytes(u.Used), detector.FormatBytes(u.Avail))
		if u.InodesTotal > 0 {
			fmt.Fprintf(&b, ", inodes %.0f%%", float64(u.InodesUsed)/float64(u.InodesTotal)*100)
		}
		b.WriteString("\n")
	}
	for _, res := range []string{"cpu", "memory", "io"} {
		raw, err := os.ReadFile(filepath.Join(proc, "pressure", res))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				fmt.Fprintf(&b, "pressure %s %s: %s %s\n", res, f[0], f[1], f[2])
			}
		}
	}

	procs, err := t.processes(ctx)
	if err != nil {
		fmt.Fprintf(&b, "processes: %v\n", err)
		return b.String(), nil
	}
	if len(procs) < 5 {
		fmt.Fprintf(&b, "only %d processes are visible: nodux runs in its own PID namespace (run its container with --pid=host to see the host's)\n", len(procs))
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].rss > procs[j].rss })
	b.WriteString("top processes by memory:\n")
	for i, p := range procs {
		if i == 8 {
			break
		}
		fmt.Fprintf(&b, "  %s pid %d: %s\n", detector.FormatBytes(p.rss), p.pid, p.cmd)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].cpu > procs[j].cpu })
	b.WriteString("top processes by CPU over the last second (100% = one core):\n")
	for i, p := range procs {
		if i == 5 || p.cpu < 0.5 {
			break
		}
		fmt.Fprintf(&b, "  %.0f%% pid %d: %s\n", p.cpu, p.pid, p.cmd)
	}
	return b.String(), nil
}

type process struct {
	pid int
	cmd string
	rss uint64
	cpu float64 // percent of one core
}

// clockTicks is USER_HZ, which is 100 on every Linux architecture nodux
// is built for.
const clockTicks = 100

// processes reads every visible process's memory and its CPU use over
// cpuSample.
func (t *Toolbox) processes(ctx context.Context) ([]process, error) {
	proc := t.cfg.ProcPath
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	var procs []process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		dir := filepath.Join(proc, e.Name())
		mem, err := readMeminfo(filepath.Join(dir, "status"))
		if err != nil {
			continue
		}
		procs = append(procs, process{pid: pid, cmd: cmdline(dir), rss: mem["VmRSS"]})
	}

	before := make(map[int]uint64, len(procs))
	for _, p := range procs {
		before[p.pid] = cpuTicks(filepath.Join(proc, strconv.Itoa(p.pid), "stat"))
	}
	start := time.Now()
	select {
	case <-time.After(t.cpuSample):
	case <-ctx.Done():
		return procs, nil
	}
	secs := time.Since(start).Seconds()
	for i, p := range procs {
		after := cpuTicks(filepath.Join(proc, strconv.Itoa(p.pid), "stat"))
		if after > before[p.pid] && secs > 0 {
			procs[i].cpu = float64(after-before[p.pid]) / clockTicks / secs * 100
		}
	}
	return procs, nil
}

func cmdline(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	cmd := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
	if err != nil || cmd == "" {
		comm, _ := os.ReadFile(filepath.Join(dir, "comm"))
		cmd = "[" + strings.TrimSpace(string(comm)) + "]"
	}
	return detector.Truncate(cmd, 120)
}

// cpuTicks is utime+stime from /proc/<pid>/stat. The command name in
// field 2 can contain spaces and parentheses, so fields are counted
// from the last ")".
func cpuTicks(path string) uint64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	// After the name: state(3) ... utime(14) stime(15), so 11 and 12 here.
	if len(f) < 13 {
		return 0
	}
	utime, _ := strconv.ParseUint(f[11], 10, 64)
	stime, _ := strconv.ParseUint(f[12], 10, 64)
	return utime + stime
}

func countCPUs(statPath string) int {
	f, err := os.Open(statPath)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	return n
}

// readMeminfo reads "Key: value kB" lines (/proc/meminfo, and the
// memory lines of /proc/<pid>/status), in bytes.
func readMeminfo(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			n *= 1024
		}
		out[key] = n
	}
	return out, sc.Err()
}
