package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/history"
)

func (t *Toolbox) alertHistory(ctx context.Context, subject string, hours int) (string, error) {
	subject = strings.TrimSpace(subject)
	if hours <= 0 {
		hours = 24
	}
	hours = min(hours, maxHistoryHrs)
	now := t.now()
	var b strings.Builder

	if t.cfg.OpenAlerts != nil {
		var open []string
		for _, issue := range t.cfg.OpenAlerts() {
			name := issue.Container.Name
			if name == "" {
				name = issue.Resource
			}
			if subject != "" && name != subject {
				continue
			}
			open = append(open, fmt.Sprintf("- %s %s, open for %s: %s", issue.Detector, name,
				now.Sub(issue.DetectedAt).Round(time.Minute), issue.Message))
		}
		if len(open) == 0 {
			b.WriteString("Open alerts: none.\n")
		} else {
			b.WriteString("Open alerts:\n" + strings.Join(open, "\n") + "\n")
		}
	}
	if t.cfg.History == nil {
		b.WriteString("No alert history is kept (state_dir is off).\n")
		return b.String(), nil
	}

	alerts, err := t.cfg.History.Alerts(ctx, history.Query{Subject: subject, Since: now.Add(-time.Duration(hours) * time.Hour), Limit: maxHistory})
	if err != nil {
		return "", err
	}
	what := "all containers and the host"
	if subject != "" {
		what = subject
	}
	if len(alerts) == 0 {
		fmt.Fprintf(&b, "No alerts for %s in the last %dh.\n", what, hours)
		return b.String(), nil
	}
	fmt.Fprintf(&b, "Alerts for %s in the last %dh, newest first:\n", what, hours)
	for _, a := range alerts {
		fmt.Fprintf(&b, "%s %s %s %s: %s", a.Time.UTC().Format("2006-01-02 15:04 UTC"), a.State, a.Detector, a.Subject, a.Message)
		if a.IncidentID != 0 {
			fmt.Fprintf(&b, " [incident %d]", a.IncidentID)
		}
		b.WriteString("\n")
	}
	if len(alerts) == maxHistory {
		fmt.Fprintf(&b, "(only the latest %d shown)\n", maxHistory)
	}
	return b.String(), nil
}
