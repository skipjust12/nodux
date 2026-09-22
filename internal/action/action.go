// Package action определяет контракт для реакций на обнаруженные проблемы.
// Сейчас есть только ConsoleAction (печать в stdout), но интерфейс задуман
// так, чтобы позже добавить действия вроде отправки в Slack/webhook/restart
// без изменения движка.
package action

import (
	"context"

	"github.com/skipjust12/nodux/internal/detector"
)

type Action interface {
	Name() string
	Run(ctx context.Context, issue detector.Issue) error
}
