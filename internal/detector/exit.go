package detector

import (
	"encoding/json"
	"fmt"
)

// ExitDetector fires when a container's main process exits on its own
// with a non-zero code: a crash, as opposed to someone stopping it.
//
// The daemon doesn't record whether a stop was requested, but the event
// stream shows it: docker stop / kill / restart / rm -f all emit one or
// more "kill" events before "die", while a crash is a bare "die". So a
// "die" is only reported if no stopping "kill" was seen since the last
// "start". A "kill" with a signal the process is meant to survive
// (docker kill -s HUP) doesn't count as a stop.
//
// An OOM kill also ends in "die" (exit 137) right after the "oom" event;
// when the OOM detector is enabled that exit is left to it, so the same
// failure isn't reported twice.
//
// Only the event loop touches it (SaveState runs while that loop is
// paused), so it needs no lock.
type ExitDetector struct {
	ignoreCodes map[int]struct{}
	skipOOM     bool
	// Per-container state, reset on "start" and dropped on "destroy".
	stops stopTracker
	oomed map[string]bool
}

func NewExitDetector(ignoreExitCodes []int, skipOOM bool) *ExitDetector {
	ignore := make(map[int]struct{}, len(ignoreExitCodes))
	for _, c := range ignoreExitCodes {
		ignore[c] = struct{}{}
	}
	return &ExitDetector{
		ignoreCodes: ignore,
		skipOOM:     skipOOM,
		stops:       make(stopTracker),
		oomed:       make(map[string]bool),
	}
}

func (d *ExitDetector) Name() string { return "exit" }

func (d *ExitDetector) HandleEvent(ev ContainerEvent) *Issue {
	d.stops.observe(ev)
	switch ev.Action {
	case "start", "destroy":
		delete(d.oomed, ev.ID)
	case "oom":
		d.oomed[ev.ID] = true
	case "die":
		if d.stops[ev.ID] {
			return nil
		}
		oomed := d.oomed[ev.ID]
		if d.skipOOM && oomed {
			return nil
		}
		if d.ignored(ev) {
			return nil
		}
		hint := exitCodeHint(ev.ExitCode)
		if oomed {
			hint = " (OOM killed)"
		}
		return &Issue{
			Detector: d.Name(),
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("container exited unexpectedly with code %d%s", ev.ExitCode, hint),
			Container: ContainerSnapshot{
				ID:        ev.ID,
				Name:      ev.Name,
				ExitCode:  ev.ExitCode,
				OOMKilled: oomed,
				Labels:    ev.Labels,
			},
			DetectedAt: ev.Time,
		}
	}
	return nil
}

// ignored applies ignore_exit_codes, or the container's own
// nodux.exit.ignore label instead.
func (d *ExitDetector) ignored(ev ContainerEvent) bool {
	if codes, ok := labelInts(ev.Labels, "nodux.exit.ignore"); ok {
		for _, c := range codes {
			if c == ev.ExitCode {
				return true
			}
		}
		return false
	}
	_, ignored := d.ignoreCodes[ev.ExitCode]
	return ignored
}

type exitSaved struct {
	Stops map[string]bool `json:"stops,omitempty"`
	OOMed map[string]bool `json:"oomed,omitempty"`
}

func (d *ExitDetector) SaveState() ([]byte, error) {
	return json.Marshal(exitSaved{Stops: d.stops, OOMed: d.oomed})
}

func (d *ExitDetector) LoadState(data []byte) error {
	var saved exitSaved
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	for id, v := range saved.Stops {
		d.stops[id] = v
	}
	for id, v := range saved.OOMed {
		d.oomed[id] = v
	}
	return nil
}

// exitCodeHint decodes the common conventions for container exit codes.
func exitCodeHint(code int) string {
	switch {
	case code == 125:
		return " (docker run itself failed)"
	case code == 126:
		return " (command not executable)"
	case code == 127:
		return " (command not found)"
	case code == 137:
		return " (SIGKILL from outside docker)"
	case code == 139:
		return " (segmentation fault)"
	case code > 128 && code < 128+65:
		return fmt.Sprintf(" (killed by signal %d)", code-128)
	}
	return ""
}
