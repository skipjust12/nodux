package action

import (
	"context"
	"path"

	"github.com/skipjust12/nodux/internal/detector"
)

// Route decides which alerts a receiver gets.
type Route struct {
	// Severities the receiver gets; empty = all. A resolution goes where
	// the alert went.
	Severities []string
	// Detectors (globs) the receiver gets; empty = all.
	Detectors []string
	// SendResolved sends "resolved" messages too.
	SendResolved bool
	// Digest sends the periodic digest too.
	Digest bool
}

// Routed is a receiver behind a Route: it gets the alerts of each
// notification that the route lets through, and nothing if none are
// left. Silenced alerts never get through.
type Routed struct {
	Action
	route Route
}

func NewRouted(a Action, r Route) *Routed { return &Routed{Action: a, route: r} }

func (r *Routed) Send(ctx context.Context, n Notification) error {
	if n.Digest != nil {
		if !r.route.Digest {
			return nil
		}
		return r.Action.Send(ctx, n)
	}
	var kept []detector.Issue
	for _, issue := range n.Alerts {
		if r.route.Matches(issue) {
			kept = append(kept, issue)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	n.Alerts = kept
	if !firing(kept) {
		// Only resolutions are left; the analysis was about the alerts.
		n.Summary = ""
	}
	return r.Action.Send(ctx, n)
}

// Matches reports whether the route lets the issue through.
func (r Route) Matches(issue detector.Issue) bool {
	if issue.Silenced || (issue.Resolved && !r.SendResolved) {
		return false
	}
	if len(r.Severities) > 0 && !contains(r.Severities, issue.Severity) {
		return false
	}
	if len(r.Detectors) == 0 {
		return true
	}
	for _, pattern := range r.Detectors {
		if ok, _ := path.Match(pattern, issue.Detector); ok {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
