package detector

import "fmt"

// ExitDetector fires when a container's main process exits on its own
// with a non-zero code: a crash, as opposed to someone stopping it.
//
// The daemon doesn't record whether a stop was requested, but the event
// stream shows it: docker stop / kill / restart / rm -f all emit one or
// more "kill" events before "die", while a crash is a bare "die". So a
// "die" is only reported if no "kill" was seen since the last "start".
//
// An OOM kill also ends in "die" (exit 137) right after the "oom" event;
// when the OOM detector is enabled that exit is left to it, so the same
// failure isn't reported twice.
type ExitDetector struct {
	ignoreCodes map[int]struct{}
	skipOOM     bool
	// Per-container flags, reset on "start" and dropped on "destroy".
	killed map[string]bool
	oomed  map[string]bool
}

func NewExitDetector(ignoreExitCodes []int, skipOOM bool) *ExitDetector {
	ignore := make(map[int]struct{}, len(ignoreExitCodes))
	for _, c := range ignoreExitCodes {
		ignore[c] = struct{}{}
	}
	return &ExitDetector{
		ignoreCodes: ignore,
		skipOOM:     skipOOM,
		killed:      make(map[string]bool),
		oomed:       make(map[string]bool),
	}
}

func (d *ExitDetector) Name() string { return "exit" }

func (d *ExitDetector) HandleEvent(ev ContainerEvent) *Issue {
	switch ev.Action {
	case "start", "destroy":
		delete(d.killed, ev.ID)
		delete(d.oomed, ev.ID)
	case "kill":
		d.killed[ev.ID] = true
	case "oom":
		d.oomed[ev.ID] = true
	case "die":
		if d.killed[ev.ID] {
			return nil
		}
		oomed := d.oomed[ev.ID]
		if d.skipOOM && oomed {
			return nil
		}
		if _, ignored := d.ignoreCodes[ev.ExitCode]; ignored {
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
			},
			DetectedAt: ev.Time,
		}
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
