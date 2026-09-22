// Package action defines the contract for reacting to detected
// problems. Right now there's only ConsoleAction (print to stdout), but
// the interface is meant to let us add actions like Slack/webhook/restart
// later without touching the engine.
package action

import (
	"context"

	"github.com/skipjust12/nodux/internal/detector"
)

type Action interface {
	Name() string
	Run(ctx context.Context, issue detector.Issue) error
}
