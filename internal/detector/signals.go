package detector

import (
	"strconv"
	"strings"
)

// Linux signal numbers. Containers run Linux, so these hold whatever
// OS nodux itself is built for.
var signalNumbers = map[string]int{
	"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "TRAP": 5, "ABRT": 6, "IOT": 6,
	"BUS": 7, "FPE": 8, "KILL": 9, "USR1": 10, "SEGV": 11, "USR2": 12,
	"PIPE": 13, "ALRM": 14, "TERM": 15, "STKFLT": 16, "CHLD": 17,
	"CONT": 18, "STOP": 19, "TSTP": 20, "TTIN": 21, "TTOU": 22, "URG": 23,
	"XCPU": 24, "XFSZ": 25, "VTALRM": 26, "PROF": 27, "WINCH": 28,
	"IO": 29, "POLL": 29, "PWR": 30, "SYS": 31,
}

const sigRTMIN = 34

// ParseSignal parses a signal as Docker writes it: a number ("15"), a
// name with or without the SIG prefix ("SIGTERM", "term"), or a
// real-time signal ("SIGRTMIN+3", used by systemd images). 0 if it
// can't be parsed.
func ParseSignal(s string) int {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	s = strings.TrimPrefix(s, "SIG")
	if n, ok := signalNumbers[s]; ok {
		return n
	}
	if rest, ok := strings.CutPrefix(s, "RTMIN"); ok {
		if rest == "" {
			return sigRTMIN
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(rest, "+")); err == nil {
			return sigRTMIN + n
		}
	}
	return 0
}

// isStopRequest reports whether a "kill" event is someone stopping the
// container, as opposed to poking it with a signal it's expected to
// survive (docker kill -s HUP to reload nginx, USR1 to reopen logs).
// docker stop / restart / rm -f / compose down send the container's
// stop signal and then SIGKILL; docker kill defaults to SIGKILL.
func isStopRequest(ev ContainerEvent) bool {
	switch ev.Signal {
	case 0:
		return true // unknown: assume a stop rather than risk a false crash alert
	case 2, 3, 9, 15: // INT, QUIT, KILL, TERM
		return true
	}
	return ev.Signal == ev.StopSignal
}

// stopTracker remembers, per container, whether a stop was requested
// since it last started, so a following "die" can be told apart from a
// crash.
type stopTracker map[string]bool

func (t stopTracker) observe(ev ContainerEvent) {
	switch ev.Action {
	case "start", "destroy":
		delete(t, ev.ID)
	case "kill":
		if isStopRequest(ev) {
			t[ev.ID] = true
		}
	}
}
