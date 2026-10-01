package detector

import (
	"fmt"
	"log/slog"
	"math"
	"time"
)

// DiskForecastDetector predicts when a filesystem will run out of space
// from how fast it has been filling: a least-squares line through the
// free space samples of the last window. A static threshold says little
// on its own; 90% of a 20 GB disk is 2 GB of headroom, which json-file
// logs can eat overnight. This one fires when the projected time to full
// drops under the horizon, and the episode ends once it's back above
// twice the horizon (or the disk stops filling).
//
// It needs samples covering at least a quarter of the window before it
// says anything, so a single big write right after startup doesn't
// trigger it. Only space is forecast, not inodes.
type DiskForecastDetector struct {
	paths   []string
	window  time.Duration
	horizon time.Duration
	samples map[string][]diskSample
	firing  map[string]bool
	failing map[string]bool
	statfs  func(path string) (DiskUsage, error)
	now     func() time.Time
}

type diskSample struct {
	at    time.Time
	avail float64 // bytes
}

func NewDiskForecastDetector(paths []string, window, horizon time.Duration) *DiskForecastDetector {
	return &DiskForecastDetector{
		paths:   paths,
		window:  window,
		horizon: horizon,
		samples: make(map[string][]diskSample),
		firing:  make(map[string]bool),
		failing: make(map[string]bool),
		statfs:  statfs,
		now:     time.Now,
	}
}

func (d *DiskForecastDetector) Name() string { return "host_disk_forecast" }

func (d *DiskForecastDetector) Check() []*Issue {
	now := d.now()
	var issues []*Issue
	for _, path := range d.paths {
		u, err := d.statfs(path)
		if err != nil {
			if !d.failing[path] {
				slog.Warn("disk forecast check failed", "path", path, "error", err)
				d.failing[path] = true
			}
			if d.firing[path] {
				// Keep the episode open on what we last knew.
				if issue := d.forecast(path, now); issue != nil {
					issues = append(issues, issue)
				}
			}
			continue
		}
		delete(d.failing, path)

		s := append(d.samples[path], diskSample{at: now, avail: float64(u.Avail)})
		cutoff := now.Add(-d.window)
		for len(s) > 0 && s[0].at.Before(cutoff) {
			s = s[1:]
		}
		d.samples[path] = s

		if issue := d.forecast(path, now); issue != nil {
			issues = append(issues, issue)
		}
	}
	return issues
}

// forecast fits the samples and decides whether the episode is (still)
// open.
func (d *DiskForecastDetector) forecast(path string, now time.Time) *Issue {
	s := d.samples[path]
	if len(s) < 3 || s[len(s)-1].at.Sub(s[0].at) < d.window/4 {
		return nil
	}
	slope := fitSlope(s) // bytes per second, negative when filling
	avail := s[len(s)-1].avail

	eta := time.Duration(math.MaxInt64)
	if slope < 0 {
		secs := avail / -slope
		if secs < float64(math.MaxInt64/int64(time.Second)) {
			eta = time.Duration(secs * float64(time.Second))
		}
	}

	limit := d.horizon
	if d.firing[path] {
		limit = 2 * d.horizon
	}
	if eta > limit {
		d.firing[path] = false
		return nil
	}
	d.firing[path] = true

	rate := math.Round(-slope*3600/(1<<20)) * (1 << 20) // to the MiB
	return &Issue{
		Detector: d.Name(),
		Severity: SeverityWarning,
		Message: fmt.Sprintf("disk %s will be full in ~%s at the current rate (%s free, filling at %s/h over the last %s)",
			path, FormatETA(eta), formatBytes(uint64(avail)), formatBytes(uint64(rate)), formatWindow(s[len(s)-1].at.Sub(s[0].at))),
		Resource:   path,
		DetectedAt: now,
	}
}

// fitSlope is the least-squares slope of avail over time, per second.
func fitSlope(s []diskSample) float64 {
	t0 := s[0].at
	var n, sx, sy, sxx, sxy float64
	for _, p := range s {
		x := p.at.Sub(t0).Seconds()
		n++
		sx += x
		sy += p.avail
		sxx += x * x
		sxy += x * p.avail
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

// FormatETA renders a time-to-event roughly, the way a forecast should
// be read: 40m, 6h, 3d.
func FormatETA(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "1m"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Round(time.Hour).Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Round(24*time.Hour).Hours()/24))
	}
}

func formatWindow(d time.Duration) string {
	m := int(d.Round(time.Minute).Minutes())
	switch {
	case m < 60:
		return fmt.Sprintf("%dm", m)
	case m%60 == 0:
		return fmt.Sprintf("%dh", m/60)
	default:
		return fmt.Sprintf("%dh%dm", m/60, m%60)
	}
}
