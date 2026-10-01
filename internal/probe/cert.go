package probe

import (
	"fmt"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

// CertDetector fires when a certificate a probe saw expires within warn
// (a warning) or within critical, or already has (critical). The episode
// escalates from warning to critical as the date gets closer, and ends
// once a renewed certificate shows up. It keeps reporting from the last
// certificate it saw while the target is unreachable: the probe alert
// covers the outage, and the expiry date doesn't change.
type CertDetector struct {
	prober   *Prober
	warn     time.Duration
	critical time.Duration
	now      func() time.Time
}

func NewCertDetector(p *Prober, warn, critical time.Duration) *CertDetector {
	return &CertDetector{prober: p, warn: warn, critical: critical, now: time.Now}
}

func (d *CertDetector) Name() string { return "tls_cert" }

func (d *CertDetector) Check() []*detector.Issue {
	now := d.now()
	var issues []*detector.Issue
	for _, c := range d.prober.Certs() {
		left := c.NotAfter.Sub(now)
		if left > d.warn {
			continue
		}
		severity := detector.SeverityWarning
		if left <= d.critical {
			severity = detector.SeverityCritical
		}
		what := "certificate " + c.Subject
		if !c.Leaf {
			what = "intermediate certificate " + c.Subject
		}
		when := "expires in " + days(left)
		if left <= 0 {
			when = "expired " + days(-left) + " ago"
		}
		issues = append(issues, &detector.Issue{
			Detector: d.Name(),
			Severity: severity,
			Message: fmt.Sprintf("%s %s (%s, issued by %s)",
				what, when, c.NotAfter.UTC().Format("2006-01-02 15:04 MST"), c.Issuer),
			Resource:   c.Target,
			DetectedAt: now,
		})
	}
	return issues
}

func days(d time.Duration) string {
	switch n := int(d.Hours() / 24); {
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case n == 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", n)
	}
}
