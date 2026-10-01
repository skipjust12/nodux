package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/incident"
	"github.com/skipjust12/nodux/internal/llm"
)

const (
	batchQueue     = 64
	analyzeBatch   = 8
	analyzeWorkers = 4

	// What the analyzer gets to see of a container's past.
	historyWindow = 7 * 24 * time.Hour
	historyAlerts = 10
	// An image change older than this isn't "a recent deploy".
	recentDeploy = 7 * 24 * time.Hour
)

// dispatch files queued alerts under incidents and hands batches that
// are due to the delivery goroutine, until the queue is closed. Then
// it flushes everything still held back, so nothing is lost on
// shutdown.
func (e *Engine) dispatch(ctx context.Context) {
	batches := make(chan incident.Batch, batchQueue)
	delivered := make(chan struct{})
	go func() {
		defer close(delivered)
		e.deliver(ctx, batches)
	}()

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		var wake <-chan time.Time
		if next := e.grouper.Next(); !next.IsZero() {
			timer.Reset(max(next.Sub(e.now()), 0))
			wake = timer.C
		}
		select {
		case issue, ok := <-e.queue:
			if !ok {
				for _, b := range e.grouper.Flush() {
					batches <- b
				}
				close(batches)
				<-delivered
				return
			}
			e.grouper.Add(issue)
		case <-wake:
		}
		for _, b := range e.grouper.Due(e.now()) {
			batches <- b
		}
	}
}

// deliver analyzes batches (several at once when they pile up) and
// sends them, in order. Once ctx is cancelled (shutting down), analysis
// is skipped so pending alerts go out right away.
func (e *Engine) deliver(ctx context.Context, batches <-chan incident.Batch) {
	for first := range batches {
		group := []incident.Batch{first}
	drain:
		for len(group) < analyzeBatch {
			select {
			case b, ok := <-batches:
				if !ok {
					break drain
				}
				group = append(group, b)
			default:
				break drain
			}
		}

		summaries := e.analyze(ctx, group)
		for i, b := range group {
			e.send(b, summaries[i])
		}
	}
}

func (e *Engine) analyze(ctx context.Context, group []incident.Batch) []string {
	summaries := make([]string, len(group))
	if e.opts.Analyzer == nil || ctx.Err() != nil {
		return summaries
	}
	sem := make(chan struct{}, analyzeWorkers)
	var wg sync.WaitGroup
	for i := range group {
		b := &group[i]
		// Resolutions only say that something is over.
		if !b.Firing() {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			summary, err := e.opts.Analyzer.Analyze(ctx, e.incidentFor(ctx, b))
			switch {
			case errors.Is(err, llm.ErrBudgetExhausted):
				slog.Debug("llm budget exhausted, sending alert without analysis", "incident", b.IncidentID)
			case err != nil:
				slog.Warn("llm analysis failed", "incident", b.IncidentID, "error", err)
			default:
				summaries[i] = summary
			}
		}()
	}
	wg.Wait()
	return summaries
}

// incidentFor gathers what the analyzer should know about a batch:
// recent image changes and earlier alerts of the containers involved.
func (e *Engine) incidentFor(ctx context.Context, b *incident.Batch) llm.Incident {
	now := e.now()
	inc := llm.Incident{
		ID:          b.IncidentID,
		Host:        e.opts.Hostname,
		Update:      b.Update,
		Alerts:      b.Alerts,
		Earlier:     b.Earlier,
		PrevSummary: b.PrevSummary,
		Containers:  make(map[string]llm.ContainerFacts),
		Now:         now,
	}
	for _, a := range b.Alerts {
		name := a.Container.Name
		if name == "" || a.Resolved {
			continue
		}
		if _, done := inc.Containers[name]; done {
			continue
		}
		var f llm.ContainerFacts
		e.mu.Lock()
		if img := e.images[name]; img != nil && !img.ChangedAt.IsZero() && now.Sub(img.ChangedAt) < recentDeploy {
			f.ImageChangedAt, f.PrevImage = img.ChangedAt, img.Prev
		}
		e.mu.Unlock()
		if e.opts.History != nil {
			past, err := e.opts.History.Alerts(ctx, history.Query{Subject: name, Since: now.Add(-historyWindow), Limit: historyAlerts + len(b.Earlier)})
			if err != nil {
				slog.Warn("reading alert history failed", "container", name, "error", err)
			}
			for _, p := range past {
				if b.IncidentID != 0 && p.IncidentID == b.IncidentID {
					continue // already in the prompt as part of this incident
				}
				if len(f.History) == historyAlerts {
					break
				}
				f.History = append(f.History, llm.PastAlert{Time: p.Time, Detector: p.Detector, Message: p.Message, Resolved: p.State == history.StateResolved})
			}
		}
		inc.Containers[name] = f
	}
	return inc
}

// send hands a batch to every action and records it in the history.
func (e *Engine) send(b incident.Batch, summary string) {
	if summary != "" {
		for i := range b.Alerts {
			if !b.Alerts[i].Resolved {
				b.Alerts[i].Analysis = summary
			}
		}
		e.grouper.SetSummary(b.IncidentID, summary)
	}
	n := action.Notification{IncidentID: b.IncidentID, Update: b.Update, Alerts: b.Alerts, Summary: summary}
	for _, a := range e.opts.Actions {
		if err := a.Send(context.Background(), n); err != nil {
			slog.Error("action failed", "action", a.Name(), "incident", b.IncidentID, "alerts", len(b.Alerts), "error", err)
		}
	}
	if e.opts.History != nil {
		rows := make([]history.Alert, 0, len(b.Alerts))
		for _, issue := range b.Alerts {
			rows = append(rows, history.AlertFromIssue(issue, issue.Analysis))
		}
		if err := e.opts.History.AddAlerts(context.Background(), rows); err != nil {
			slog.Warn("recording alert history failed", "error", err)
		}
	}
}
