package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
)

func (t *Toolbox) listContainers(ctx context.Context) (string, error) {
	list, err := t.visible(ctx)
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "No containers.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d containers:\n", len(list))
	for _, c := range list {
		fmt.Fprintf(&b, "- %s: %s, %s, image %s", containerName(c), c.State, c.Status, c.Image)
		if p := c.Labels[detector.LabelComposeProject]; p != "" {
			fmt.Fprintf(&b, ", compose %s/%s", p, c.Labels[detector.LabelComposeService])
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (t *Toolbox) inspect(ctx context.Context, query string) (string, error) {
	c, err := t.resolve(ctx, query)
	if err != nil {
		return "", err
	}
	in, err := t.cfg.Docker.InspectContainer(ctx, c.ID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	st := in.State
	fmt.Fprintf(&b, "name: %s (id %s)\n", containerName(c), shortID(in.ID))
	fmt.Fprintf(&b, "image: %s (%s)\n", in.Config.Image, shortID(in.Image))
	if created := parseTime(in.Created); !created.IsZero() {
		fmt.Fprintf(&b, "created: %s\n", stamp(created))
	}
	fmt.Fprintf(&b, "state: %s, restart count %d, last exit code %d", st.Status, in.RestartCount, st.ExitCode)
	if st.OOMKilled {
		b.WriteString(", OOM killed")
	}
	if st.Error != "" {
		fmt.Fprintf(&b, ", error %q", st.Error)
	}
	b.WriteString("\n")
	if started := parseTime(st.StartedAt); !started.IsZero() {
		fmt.Fprintf(&b, "started: %s\n", stamp(started))
	}
	if finished := parseTime(st.FinishedAt); !finished.IsZero() {
		fmt.Fprintf(&b, "last exited: %s\n", stamp(finished))
	}
	if h := st.Health; h != nil {
		fmt.Fprintf(&b, "health: %s, failing streak %d\n", h.Status, h.FailingStreak)
		logs := h.Log
		if len(logs) > 3 {
			logs = logs[len(logs)-3:]
		}
		for _, l := range logs {
			fmt.Fprintf(&b, "  check exited %d: %s\n", l.ExitCode, detector.Truncate(strings.TrimSpace(l.Output), 300))
		}
	}
	rp := in.HostConfig.RestartPolicy
	policy := rp.Name
	if policy == "" {
		policy = "no"
	}
	if rp.MaximumRetryCount > 0 {
		policy += fmt.Sprintf(":%d", rp.MaximumRetryCount)
	}
	fmt.Fprintf(&b, "restart policy: %s\n", policy)
	limits := "memory unlimited"
	if in.HostConfig.Memory > 0 {
		limits = "memory " + bytesStr(in.HostConfig.Memory)
	}
	if in.HostConfig.NanoCpus > 0 {
		limits += fmt.Sprintf(", cpus %.2g", float64(in.HostConfig.NanoCpus)/1e9)
	}
	fmt.Fprintf(&b, "limits: %s\n", limits)
	if cmd := append(append([]string{}, in.Config.Entrypoint...), in.Config.Cmd...); len(cmd) > 0 {
		fmt.Fprintf(&b, "command: %s\n", detector.Truncate(strings.Join(cmd, " "), 300))
	}
	if len(in.Config.Env) > 0 {
		var vars []string
		for _, e := range in.Config.Env {
			name, _, _ := strings.Cut(e, "=")
			vars = append(vars, name)
		}
		fmt.Fprintf(&b, "environment variables set (values hidden): %s\n", strings.Join(vars, ", "))
	}
	for _, m := range in.Mounts {
		src := m.Source
		if m.Type == "volume" && m.Name != "" {
			src = m.Name
		}
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		fmt.Fprintf(&b, "mount: %s %s -> %s (%s)\n", m.Type, src, m.Destination, mode)
	}
	if labels := detector.RelevantLabels(in.Config.Labels); len(labels) > 0 {
		var kv []string
		for k, v := range labels {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
		fmt.Fprintf(&b, "labels: %s\n", strings.Join(kv, ", "))
	}
	return b.String(), nil
}

func (t *Toolbox) logs(ctx context.Context, query, since, until string, tail int, contains string) (string, error) {
	c, err := t.resolve(ctx, query)
	if err != nil {
		return "", err
	}
	opts := dockerclient.LogOptions{Timestamps: true}
	if opts.Since, err = t.parseWhen(since); err != nil {
		return "", err
	}
	if opts.Until, err = t.parseWhen(until); err != nil {
		return "", err
	}
	if tail <= 0 {
		tail = defLogLines
	}
	tail = min(tail, maxLogLines)
	opts.Tail = tail
	contains = strings.ToLower(strings.TrimSpace(contains))
	if contains != "" {
		opts.Tail = maxScanLines
	}
	// TTY containers don't multiplex their logs; inspect tells.
	if in, err := t.cfg.Docker.InspectContainer(ctx, c.ID); err == nil {
		opts.TTY = in.Config.Tty
	}

	lines, err := t.cfg.Docker.ContainerLogsRange(ctx, c.ID, opts)
	if err != nil {
		return "", err
	}
	if contains != "" {
		kept := lines[:0]
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), contains) {
				kept = append(kept, l)
			}
		}
		lines = kept
	}
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	if len(lines) == 0 {
		return fmt.Sprintf("No log lines from %s in that range.", containerName(c)), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d log lines from %s:\n", len(lines), containerName(c))
	for _, l := range lines {
		b.WriteString(detector.Truncate(l, maxLineBytes))
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (t *Toolbox) stats(ctx context.Context, query string) (string, error) {
	c, err := t.resolve(ctx, query)
	if err != nil {
		return "", err
	}
	if c.State != "running" {
		return fmt.Sprintf("%s is not running (%s, %s).", containerName(c), c.State, c.Status), nil
	}
	st, err := t.cfg.Docker.ContainerStatsSampled(ctx, c.ID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", containerName(c))
	if pct, ok := st.CPUPercent(); ok {
		fmt.Fprintf(&b, "cpu: %.1f%% (100%% = one core)\n", pct)
	}
	// Without a -m limit, the "limit" in stats is the host's RAM.
	limited := false
	if in, err := t.cfg.Docker.InspectContainer(ctx, c.ID); err == nil {
		limited = in.HostConfig.Memory > 0
	}
	used, limit := st.MemoryUsed(), st.MemoryStats.Limit
	mem := fmt.Sprintf("memory: %s", detector.FormatBytes(used))
	if limited && limit > 0 {
		mem += fmt.Sprintf(" of %s limit (%.0f%%)", detector.FormatBytes(limit), float64(used)/float64(limit)*100)
	} else {
		mem += " (no memory limit)"
	}
	b.WriteString(mem + "\n")
	if th := st.CPUStats.ThrottlingData; th.Periods > 0 {
		fmt.Fprintf(&b, "cpu throttling: %d of %d periods throttled since start (%.0f%%)\n",
			th.ThrottledPeriods, th.Periods, float64(th.ThrottledPeriods)/float64(th.Periods)*100)
	}
	if st.PidsStats.Current > 0 {
		fmt.Fprintf(&b, "processes: %d\n", st.PidsStats.Current)
	}
	var rx, tx uint64
	for _, n := range st.Networks {
		rx += n.RxBytes
		tx += n.TxBytes
	}
	if rx+tx > 0 {
		fmt.Fprintf(&b, "network since start: %s in, %s out\n", detector.FormatBytes(rx), detector.FormatBytes(tx))
	}
	var rd, wr uint64
	for _, io := range st.BlkioStats.IOServiceBytesRecursive {
		switch strings.ToLower(io.Op) {
		case "read":
			rd += io.Value
		case "write":
			wr += io.Value
		}
	}
	if rd+wr > 0 {
		fmt.Fprintf(&b, "block I/O since start: %s read, %s written\n", detector.FormatBytes(rd), detector.FormatBytes(wr))
	}

	if top, err := t.cfg.Docker.ContainerTop(ctx, c.ID); err == nil && len(top.Processes) > 0 {
		fmt.Fprintf(&b, "processes (%s):\n", strings.Join(top.Titles, " "))
		for i, p := range top.Processes {
			if i == maxTopRows {
				fmt.Fprintf(&b, "... and %d more\n", len(top.Processes)-maxTopRows)
				break
			}
			b.WriteString(detector.Truncate(strings.Join(p, " "), 200) + "\n")
		}
	}
	return b.String(), nil
}
