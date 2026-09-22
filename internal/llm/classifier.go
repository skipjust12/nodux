// Package llm — точка расширения под опциональный LLM-слой. Задача LLM в
// будущем: разбирать неоднозначные срабатывания детекторов (когда чистой
// эвристики недостаточно, чтобы понять серьёзность/причину) и обогащать
// Issue классификацией. Пока это чистая заглушка без сетевых вызовов —
// движок дергает Classify после каждого сработавшего детектора, но
// NoopClassifier ничего не делает.
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
	// TODO(llm): здесь будет вызов LLM для классификации неоднозначных
	// срабатываний. Пока намеренно no-op.
	return nil
}
