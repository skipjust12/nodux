// Package action defines the contract for reacting to detected
// problems: ConsoleAction (JSON lines on stdout) and the receivers built
// on HTTPAction (webhook, Telegram, ntfy), each behind a Route that
// decides which alerts it gets. New actions plug in without touching
// the engine.
package action

import (
	"context"

	"github.com/skipjust12/nodux/internal/detector"
)

type Action interface {
	Name() string
	Run(ctx context.Context, issue detector.Issue) error
}
