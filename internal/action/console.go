package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/skipjust12/nodux/internal/detector"
)

// ConsoleAction prints a detected problem to stdout as a single JSON
// line, so it can later be shipped anywhere (journald, Loki, a file, ...).
type ConsoleAction struct{}

func NewConsole() *ConsoleAction { return &ConsoleAction{} }

func (a *ConsoleAction) Name() string { return "console" }

func (a *ConsoleAction) Run(_ context.Context, issue detector.Issue) error {
	b, err := json.Marshal(NewRecord(issue))
	if err != nil {
		return fmt.Errorf("marshal issue: %w", err)
	}
	fmt.Println(string(b))
	return nil
}
