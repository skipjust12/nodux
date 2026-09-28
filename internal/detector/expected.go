package detector

import (
	"fmt"
	"time"
)

// ExpectedDetector fires when a container that's supposed to be up
// isn't: it doesn't exist, or it's stopped. That's the case every other
// detector misses: a container that exited cleanly (code 0), or was
// never started after a reboot, raises no event worth alerting on.
//
// "restarting" counts as up here; crash loops are crashloop's business.
// A container must be down for grace before it's reported, so a
// compose recreate doesn't page anyone.
type ExpectedDetector struct {
	names     []string
	grace     time.Duration
	downSince map[string]time.Time
	now       func() time.Time
}

func NewExpectedDetector(names []string, grace time.Duration) *ExpectedDetector {
	return &ExpectedDetector{
		names:     names,
		grace:     grace,
		downSince: make(map[string]time.Time),
		now:       time.Now,
	}
}

func (d *ExpectedDetector) Name() string { return "expected" }

// Check takes the status of every container the daemon knows about, by
// name, and returns an issue for each expected one that's down.
func (d *ExpectedDetector) Check(statuses map[string]string) []*Issue {
	now := d.now()
	var issues []*Issue
	for _, name := range d.names {
		status, exists := statuses[name]
		if exists && (status == "running" || status == "restarting") {
			delete(d.downSince, name)
			continue
		}
		since, ok := d.downSince[name]
		if !ok {
			since = now
			d.downSince[name] = now
		}
		if now.Sub(since) < d.grace {
			continue
		}

		msg := "expected container does not exist"
		if exists {
			msg = fmt.Sprintf("expected container is not running (status: %s)", status)
		}
		issues = append(issues, &Issue{
			Detector:   d.Name(),
			Severity:   SeverityCritical,
			Message:    msg,
			Container:  ContainerSnapshot{Name: name, Status: status},
			DetectedAt: now,
		})
	}
	return issues
}
