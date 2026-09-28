// Package llm is the optional LLM layer: it reads an alert together
// with the container's recent logs and adds a short "probable cause"
// analysis to it before it's sent anywhere. Detection itself stays
// deterministic; the LLM only annotates what the detectors found.
package llm

import (
	"context"
	"errors"

	"github.com/skipjust12/nodux/internal/detector"
)

// ErrBudgetExhausted is returned when the hourly call budget is spent.
// The alert still goes out, just without an analysis.
var ErrBudgetExhausted = errors.New("llm: hourly call budget exhausted")

type Classifier interface {
	// Classify returns a short analysis of the issue's probable cause,
	// or "" if there's nothing to add.
	Classify(ctx context.Context, issue detector.Issue) (string, error)
}

// NoopClassifier is used when the LLM layer is disabled.
type NoopClassifier struct{}

func NewNoopClassifier() *NoopClassifier { return &NoopClassifier{} }

func (n *NoopClassifier) Classify(context.Context, detector.Issue) (string, error) {
	return "", nil
}
