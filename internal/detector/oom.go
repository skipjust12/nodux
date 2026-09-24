package detector

// OOMDetector fires when the kernel OOM killer kills a process in a
// container (the daemon's "oom" event). Event-driven on purpose: with a
// restart policy, State.OOMKilled is cleared on the next start, usually
// long before the next poll.
type OOMDetector struct{}

func NewOOMDetector() *OOMDetector { return &OOMDetector{} }

func (d *OOMDetector) Name() string { return "oom" }

func (d *OOMDetector) HandleEvent(ev ContainerEvent) *Issue {
	if ev.Action != "oom" {
		return nil
	}
	return &Issue{
		Detector: d.Name(),
		Severity: SeverityCritical,
		Message:  "container was killed by the OOM killer (memory limit reached)",
		Container: ContainerSnapshot{
			ID:        ev.ID,
			Name:      ev.Name,
			OOMKilled: true,
		},
		DetectedAt: ev.Time,
	}
}
