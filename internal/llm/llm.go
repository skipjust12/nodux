// Package llm is the optional LLM layer. It reads an incident (alerts
// that belong together, their logs, and what nodux knows about the
// containers involved), may look further with read-only tools, and adds
// a short "probable cause" note before the alert is sent. It also
// answers operators' questions from the chat bot and writes the
// digest's takeaway. Detection itself stays deterministic; the LLM only
// annotates what the detectors found.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

// ErrBudgetExhausted is returned when the hourly budget is spent. The
// alert still goes out, just without an analysis.
var ErrBudgetExhausted = errors.New("llm: hourly budget exhausted")

// Analyzer annotates an incident with its probable cause.
type Analyzer interface {
	Analyze(ctx context.Context, inc Incident) (string, error)
}

// Incident is one batch of alerts to analyze, with context.
type Incident struct {
	ID     int64
	Host   string
	Update bool
	Alerts []detector.Issue
	// Earlier are the incident's alerts that were already reported, and
	// PrevSummary the analysis sent with them.
	Earlier     []detector.Issue
	PrevSummary string
	// Containers holds what nodux knows about each container involved,
	// by name.
	Containers map[string]ContainerFacts
	Now        time.Time
}

// ContainerFacts is context about a container that isn't in its
// inspect data.
type ContainerFacts struct {
	// ImageChangedAt is when nodux first saw the container run its
	// current image, having seen it run PrevImage before. Zero if nodux
	// hasn't seen it change.
	ImageChangedAt time.Time
	PrevImage      string
	// History is the container's earlier alerts, newest first.
	History []PastAlert
}

type PastAlert struct {
	Time     time.Time
	Detector string
	Message  string
	Resolved bool
}

// ToolSpec describes a tool the model may call.
type ToolSpec struct {
	Name        string
	Description string
	Properties  map[string]any // JSON schema properties of the input object
	Required    []string
}

// Toolbox runs tools for the model. Every tool must be read-only, and
// its output must already be redacted.
type Toolbox interface {
	Tools() []ToolSpec
	Call(ctx context.Context, name string, input json.RawMessage) (string, error)
}

// Usage is the token usage of one API call, for the digest's cost line.
type Usage struct {
	Run        string // groups the calls of one analysis or answer
	Purpose    string // incident, question, digest
	Model      string // the model that served the call
	Input      int64  // uncached input tokens
	Output     int64
	CacheRead  int64
	CacheWrite int64
}
