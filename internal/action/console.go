package action

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// ConsoleAction prints alerts to stdout as JSON lines, one per alert
// (with its incident_id), so they can be shipped anywhere (journald,
// Loki, a file, ...). A digest is one line of kind "digest".
type ConsoleAction struct {
	mu  sync.Mutex
	out io.Writer
}

func NewConsole() *ConsoleAction { return &ConsoleAction{out: os.Stdout} }

func (a *ConsoleAction) Name() string { return "console" }

func (a *ConsoleAction) Send(_ context.Context, n Notification) error {
	var lines [][]byte
	if n.Digest != nil {
		b, err := json.Marshal(NewDigestRecord(n.Digest))
		if err != nil {
			return fmt.Errorf("marshal digest: %w", err)
		}
		lines = append(lines, b)
	}
	for _, issue := range n.Alerts {
		b, err := json.Marshal(NewRecord(issue))
		if err != nil {
			return fmt.Errorf("marshal issue: %w", err)
		}
		lines = append(lines, b)
	}
	// One write per line, never interleaved with a concurrent digest.
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range lines {
		if _, err := a.out.Write(append(l, '\n')); err != nil {
			return err
		}
	}
	return nil
}
