// Package llm is the extension point for an optional future LLM layer.
// Its eventual job: triage ambiguous detector hits (when plain
// heuristics aren't enough to judge severity/cause) and enrich the
// Issue with a classification. For now it's a pure stub with no network
// calls — the engine calls Classify after every detector hit, but
// NoopClassifier does nothing.
package llm

import (
	"context"

	"github.com/skipjust12/nodux/internal/detector"
)

type Classifier interface {
	Classify(ctx context.Context, issue detector.Issue) error
}

type NoopClassifier struct{}

func NewNoopClassifier() *NoopClassifier { return &NoopClassifier{} }

func (n *NoopClassifier) Classify(_ context.Context, _ detector.Issue) error {
	// TODO(llm): call an LLM here to classify ambiguous detector hits.
	// Intentionally a no-op for now.
	return nil
}
