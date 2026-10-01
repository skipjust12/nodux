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
	slackMaxMessage = 1900 // Discord's /slack endpoint rejects text over 2000
)

// slackText renders an issue as Slack mrkdwn, kept under the length
// Discord accepts: log lines are dropped oldest-first until it fits.
func slackText(issue detector.Issue) string {
	var head strings.Builder
	fmt.Fprintf(&head, "*%s*", headline(issue))
	if s := subject(issue); s != "" {
		fmt.Fprintf(&head, " `%s`", escapeCode(s))
	}
	if issue.Host != "" {
		fmt.Fprintf(&head, " on %s", issue.Host)
	}
	fmt.Fprintf(&head, ": %s", issue.Message)
	if issue.Analysis != "" {
		fmt.Fprintf(&head, "\n> %s", strings.ReplaceAll(detector.Truncate(issue.Analysis, slackAnalysis), "\n", "\n> "))
	}
	text := detector.Truncate(head.String(), slackMaxMessage)

	lines := lastLines(issue.Logs, slackLogLines, slackLineMax)
	for i, l := range lines {
		lines[i] = escapeCode(l)
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
