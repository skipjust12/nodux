// Package action defines the contract for sending what nodux found:
// ConsoleAction (JSON lines on stdout) and the receivers built on
// HTTPAction (webhook, Telegram, ntfy), each behind a Route that decides
// which alerts it gets. New actions plug in without touching the engine.
package action

import (
	"context"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

// Notification is one message: alerts that belong together (a batch of
// one incident, or a single alert when grouping is off), or a digest.
type Notification struct {
	IncidentID int64
	// Update is set when this incident was already reported before.
	Update bool
	Alerts []detector.Issue
	// Summary is the LLM layer's note on the batch, if any. It's also
	// in the Analysis of each firing alert.
	Summary string
	// Digest is set (and Alerts empty) for a periodic digest.
	Digest *Digest
}

// Digest is the periodic report.
type Digest struct {
	Host     string
	Title    string // "Daily digest"
	From, To time.Time
	// Text is the report for people, in Slack mrkdwn.
	Text string
	// Data is the same report as structured data, for JSON consumers.
	Data any
}

type Action interface {
	Name() string
	Send(ctx context.Context, n Notification) error
}
