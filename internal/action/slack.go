package action

import (
	"fmt"
	"strings"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	slackLogLines   = 5
	slackLineMax    = 200
	slackAnalysis   = 500
	slackItemMax    = 300
	slackMaxMessage = 1900 // Discord's /slack endpoint rejects text over 2000
)

// slackNotification renders a notification as Slack mrkdwn, kept under
// the length Discord accepts. A lone alert looks the way it always has;
// a batch gets one header for the incident, the summary, and a line per
// alert.
func slackNotification(n Notification) string {
	if n.Digest != nil {
		return fit(n.Digest.Text)
	}
	if len(n.Alerts) == 1 {
		suffix := ""
		if n.IncidentID != 0 && n.Update {
			suffix = fmt.Sprintf(" (incident #%d)", n.IncidentID)
		}
		return slackText(n.Alerts[0], suffix)
	}

	var head strings.Builder
	label, firing, resolved := batchLabel(n.Alerts)
	fmt.Fprintf(&head, "*[%s] incident #%d*", label, n.IncidentID)
	if n.Update {
		head.WriteString(" (update)")
	}
	if host := n.Alerts[0].Host; host != "" {
		fmt.Fprintf(&head, " on %s", host)
	}
	switch {
	case firing > 0 && resolved > 0:
		fmt.Fprintf(&head, ": %d new, %d resolved", firing, resolved)
	case firing > 0:
		fmt.Fprintf(&head, ": %d alerts", firing)
	default:
		fmt.Fprintf(&head, ": %d resolved", resolved)
	}
	if n.Summary != "" {
		head.WriteString("\n" + quote(n.Summary))
	}
	for _, issue := range n.Alerts {
		item := "*" + issue.Detector + "*"
		if issue.Resolved {
			item = "resolved " + item
		}
		if s := subject(issue); s != "" {
			item += fmt.Sprintf(" `%s`", escapeCode(s))
		}
		fmt.Fprintf(&head, "\n• %s", detector.Truncate(item+": "+issue.Message, slackItemMax))
	}
	text := fit(head.String())

	// The logs of the first firing container alert, if they fit.
	for _, issue := range n.Alerts {
		if !issue.Resolved && len(issue.Logs) > 0 {
			return withLogs(text, issue.Logs)
		}
	}
	return text
}

func batchLabel(alerts []detector.Issue) (label string, firing, resolved int) {
	label = "RESOLVED"
	for _, a := range alerts {
		if a.Resolved {
			resolved++
			continue
		}
		firing++
		switch {
		case a.Severity == detector.SeverityCritical:
			label = "CRITICAL"
		case label == "RESOLVED":
			label = strings.ToUpper(a.Severity)
		}
	}
	return label, firing, resolved
}

// slackText renders a single alert. Log lines are dropped oldest-first
// until it fits.
func slackText(issue detector.Issue, suffix string) string {
	var head strings.Builder
	label := strings.ToUpper(issue.Severity)
	if issue.Resolved {
		label = "RESOLVED"
	}
	fmt.Fprintf(&head, "*[%s] %s*", label, issue.Detector)
	if s := subject(issue); s != "" {
		fmt.Fprintf(&head, " `%s`", escapeCode(s))
	}
	if issue.Host != "" {
		fmt.Fprintf(&head, " on %s", issue.Host)
	}
	head.WriteString(suffix)
	fmt.Fprintf(&head, ": %s", issue.Message)
	if issue.Analysis != "" {
		head.WriteString("\n" + quote(issue.Analysis))
	}
	return withLogs(fit(head.String()), issue.Logs)
}

// fit cuts a message to the limit, "…" included.
func fit(s string) string {
	return detector.Truncate(s, slackMaxMessage-len("…"))
}

func quote(s string) string {
	return "> " + strings.ReplaceAll(detector.Truncate(s, slackAnalysis), "\n", "\n> ")
}

// withLogs appends the last few log lines as a code block, dropping
// the oldest until the message fits.
func withLogs(text string, logs []string) string {
	if len(logs) > slackLogLines {
		logs = logs[len(logs)-slackLogLines:]
	}
	lines := make([]string, len(logs))
	for i, l := range logs {
		lines[i] = escapeCode(detector.Truncate(l, slackLineMax))
	}
	for len(lines) > 0 {
		block := "\n```\n" + strings.Join(lines, "\n") + "\n```"
		if len(text)+len(block) <= slackMaxMessage {
			return text + block
		}
		lines = lines[1:]
	}
	return text
}

func subject(issue detector.Issue) string {
	if issue.Container.Name != "" {
		return issue.Container.Name
	}
	return issue.Resource
}

// escapeCode keeps a log line from closing the code block it's in.
func escapeCode(s string) string {
	return strings.ReplaceAll(s, "```", "`​`​`")
}

// headline is "[CRITICAL] crashloop", or "[RESOLVED] crashloop".
func headline(issue detector.Issue) string {
	label := strings.ToUpper(issue.Severity)
	if issue.Resolved {
		label = "RESOLVED"
	}
	return fmt.Sprintf("[%s] %s", label, issue.Detector)
}

// lastLines returns up to n of the newest log lines, each cut to max
// bytes, in a fresh slice.
func lastLines(logs []string, n, max int) []string {
	if len(logs) > n {
		logs = logs[len(logs)-n:]
	}
	out := make([]string, len(logs))
	for i, l := range logs {
		out[i] = detector.Truncate(l, max)
	}
	return out
}

// firstLogs is the logs of the first firing alert that has any: what a
// batch message shows.
func firstLogs(alerts []detector.Issue) []string {
	for _, a := range alerts {
		if !a.Resolved && len(a.Logs) > 0 {
			return a.Logs
		}
	}
	return nil
}
