package detector

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Container labels that tune nodux per container, so a compose file can
// say what it means instead of a list of names in nodux's config:
//
//	nodux.enable=false               never check this container
//	nodux.expected=true              this container must be running
//	nodux.<detector>.enable=false    turn one detector off (crashloop,
//	                                 unhealthy, oom, exit, memory,
//	                                 cpu_throttle)
//	nodux.memory.threshold=80        percent of the memory limit
//	nodux.memory.for=2m              how long it has to stay there
//	nodux.crashloop.threshold=5      restarts...
//	nodux.crashloop.window=10m       ...within this window
//	nodux.exit.ignore=0,143          exit codes that aren't a crash
//
// Durations take Go syntax (90s, 5m) or plain seconds. A label with a
// value that doesn't parse is ignored with a warning.
const (
	LabelPrefix   = "nodux."
	LabelEnable   = "nodux.enable"
	LabelExpected = "nodux.expected"

	LabelComposeProject = "com.docker.compose.project"
	LabelComposeService = "com.docker.compose.service"
)

// Excluded reports whether a container opted out with nodux.enable=false.
func Excluded(labels map[string]string) bool {
	enabled, ok := labelBool(labels, LabelEnable)
	return ok && !enabled
}

// Enabled reports whether the named detector is on for a container:
// everything is, unless nodux.<detector>.enable=false.
func Enabled(labels map[string]string, detector string) bool {
	enabled, ok := labelBool(labels, LabelPrefix+detector+".enable")
	return !ok || enabled
}

// ExpectedByLabel reports whether a container is declared as one that
// must be running (nodux.expected=true).
func ExpectedByLabel(labels map[string]string) bool {
	expected, ok := labelBool(labels, LabelExpected)
	return ok && expected
}

// RelevantLabels keeps the labels nodux looks at (nodux.* and compose's
// project/service) out of a container's labels or an event's
// attributes, which also carry name, image, exit code and the like.
func RelevantLabels(attrs map[string]string) map[string]string {
	var out map[string]string
	for k, v := range attrs {
		if strings.HasPrefix(k, LabelPrefix) || k == LabelComposeProject || k == LabelComposeService {
			if out == nil {
				out = make(map[string]string)
			}
			out[k] = v
		}
	}
	return out
}

func labelBool(labels map[string]string, key string) (value, ok bool) {
	raw, ok := labels[key]
	if !ok {
		return false, false
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		warnLabel(key, raw, "expected true or false")
		return false, false
	}
	return v, true
}

// labelPercent reads a percentage in (0, 100].
func labelPercent(labels map[string]string, key string) (float64, bool) {
	raw, ok := labels[key]
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(raw), "%"), 64)
	if err != nil || v <= 0 || v > 100 {
		warnLabel(key, raw, "expected a percentage in (0, 100]")
		return 0, false
	}
	return v, true
}

func labelPositiveInt(labels map[string]string, key string) (int, bool) {
	raw, ok := labels[key]
	if !ok {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		warnLabel(key, raw, "expected a positive integer")
		return 0, false
	}
	return v, true
}

// labelDuration reads "90s", "5m" or plain seconds ("90").
func labelDuration(labels map[string]string, key string) (time.Duration, bool) {
	raw, ok := labels[key]
	if !ok {
		return 0, false
	}
	d, err := ParseDuration(raw)
	if err != nil || d < 0 {
		warnLabel(key, raw, "expected a duration like 90s or 5m")
		return 0, false
	}
	return d, true
}

// ParseDuration takes Go duration syntax or a plain number of seconds.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

// labelInts reads a comma-separated list of integers ("0,143").
func labelInts(labels map[string]string, key string) ([]int, bool) {
	raw, ok := labels[key]
	if !ok {
		return nil, false
	}
	var out []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			warnLabel(key, raw, "expected comma-separated integers")
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// warned keeps a bad label from being logged on every poll.
var warned sync.Map

func warnLabel(key, value, want string) {
	if _, seen := warned.LoadOrStore(key+"="+value, true); seen {
		return
	}
	slog.Warn("ignoring container label with an invalid value", "label", key, "value", value, "want", want)
}
