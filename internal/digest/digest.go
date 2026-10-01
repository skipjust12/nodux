// Package digest builds the periodic report from nodux's history: what
// broke and how often, what keeps flapping, what's still open, whose
// memory keeps growing, and what the LLM layer cost. It's deterministic;
// with the LLM layer on, a short takeaway goes on top.
package digest

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/llm"
)

const (
	maxContainers = 8
	maxHost       = 5
	maxFlapping   = 5
	maxOpen       = 8
	maxGrowth     = 5

	// An episode opening this many times in a period is flapping.
	flapThreshold = 3
	// Memory growth worth a line: at least this much, in both senses.
	growthRatio = 1.2
	growthBytes = 32 << 20
	minSamples  = 8
)

// Summarizer writes the digest's takeaway (the LLM layer).
type Summarizer interface {
	SummarizeDigest(ctx context.Context, digest string) (string, error)
}

type Builder struct {
	History    *history.Store
	OpenAlerts func() []detector.Issue // nil: no "still open" section
	Summarizer Summarizer              // nil: no takeaway
	Host       string
	Location   *time.Location // for the times people read; nil = Local
}

// Report is the digest as data (the JSON consumers' version).
type Report struct {
	From       time.Time      `json:"from"`
	To         time.Time      `json:"to"`
	Alerts     int            `json:"alerts"`
	Critical   int            `json:"critical"`
	Resolved   int            `json:"resolved"`
	Incidents  int            `json:"incidents"`
	Containers []SubjectCount `json:"containers,omitempty"`
	Host       []SubjectCount `json:"host,omitempty"`
	Flapping   []Flap         `json:"flapping,omitempty"`
	Open       []OpenAlert    `json:"open,omitempty"`
	Memory     []Growth       `json:"memory_growth,omitempty"`
	LLM        *LLMUsage      `json:"llm,omitempty"`
	Takeaway   string         `json:"takeaway,omitempty"`
}

type SubjectCount struct {
	Subject    string         `json:"subject"`
	Total      int            `json:"total"`
	ByDetector map[string]int `json:"by_detector"`
}

type Flap struct {
	Detector string `json:"detector"`
	Subject  string `json:"subject"`
	Episodes int    `json:"episodes"`
}

type OpenAlert struct {
	Detector string    `json:"detector"`
	Subject  string    `json:"subject"`
	Since    time.Time `json:"since"`
	Message  string    `json:"message"`
}

type Growth struct {
	Container string  `json:"container"`
	FromBytes uint64  `json:"from_bytes"`
	ToBytes   uint64  `json:"to_bytes"`
	Percent   float64 `json:"percent"`
	Limit     uint64  `json:"limit_bytes,omitempty"`
}

type LLMUsage struct {
	Runs       int     `json:"runs"`
	Requests   int     `json:"requests"`
	Input      int64   `json:"input_tokens"`
	Output     int64   `json:"output_tokens"`
	CacheRead  int64   `json:"cache_read_tokens"`
	CacheWrite int64   `json:"cache_write_tokens"`
	CostUSD    float64 `json:"cost_usd"`
	// CostPartial is set when some calls used a model without a known
	// price, so CostUSD undercounts.
	CostPartial bool `json:"cost_partial,omitempty"`
}

// Build makes the digest for [from, to).
func (b *Builder) Build(ctx context.Context, title string, from, to time.Time) (*action.Digest, error) {
	r, err := b.report(ctx, from, to)
	if err != nil {
		return nil, err
	}
	text := b.render(title, r)
	if b.Summarizer != nil && (r.Alerts > 0 || len(r.Open) > 0 || len(r.Memory) > 0) {
		if note, err := b.Summarizer.SummarizeDigest(ctx, text); err != nil {
			slog.Warn("digest takeaway failed", "error", err)
		} else if note = strings.TrimSpace(note); note != "" {
			r.Takeaway = note
			text += "\n> " + strings.ReplaceAll(note, "\n", "\n> ")
		}
	}
	return &action.Digest{Host: b.Host, Title: title, From: from, To: to, Text: text, Data: r}, nil
}

func (b *Builder) report(ctx context.Context, from, to time.Time) (*Report, error) {
	r := &Report{From: from, To: to}

	alerts, err := b.History.Alerts(ctx, history.Query{Since: from, Until: to})
	if err != nil {
		return nil, err
	}
	containers := make(map[string]*SubjectCount)
	host := make(map[string]*SubjectCount)
	episodes := make(map[[2]string]int)
	incidents := make(map[int64]bool)
	for _, a := range alerts {
		if a.State == history.StateResolved {
			r.Resolved++
			continue
		}
		r.Alerts++
		if a.Severity == detector.SeverityCritical {
			r.Critical++
		}
		if a.IncidentID != 0 {
			incidents[a.IncidentID] = true
		}
		if a.Episode != "" {
			episodes[[2]string{a.Detector, a.Subject}]++
		}
		m := host
		if a.Container {
			m = containers
		}
		sc := m[a.Subject]
		if sc == nil {
			sc = &SubjectCount{Subject: a.Subject, ByDetector: make(map[string]int)}
			m[a.Subject] = sc
		}
		sc.Total++
		sc.ByDetector[a.Detector]++
	}
	r.Incidents = len(incidents)
	r.Containers = sorted(containers)
	r.Host = sorted(host)
	for k, n := range episodes {
		if n >= flapThreshold {
			r.Flapping = append(r.Flapping, Flap{Detector: k[0], Subject: k[1], Episodes: n})
		}
	}
	sort.Slice(r.Flapping, func(i, j int) bool {
		if r.Flapping[i].Episodes != r.Flapping[j].Episodes {
			return r.Flapping[i].Episodes > r.Flapping[j].Episodes
		}
		return r.Flapping[i].Subject < r.Flapping[j].Subject
	})

	if b.OpenAlerts != nil {
		for _, issue := range b.OpenAlerts() {
			subject := issue.Container.Name
			if subject == "" {
				subject = issue.Resource
			}
			r.Open = append(r.Open, OpenAlert{Detector: issue.Detector, Subject: subject, Since: issue.DetectedAt, Message: issue.Message})
		}
	}

	samples, err := b.History.MemorySamples(ctx, from, to)
	if err != nil {
		return nil, err
	}
	r.Memory = growth(samples)

	calls, err := b.History.LLMCalls(ctx, from, to)
	if err != nil {
		return nil, err
	}
	if len(calls) > 0 {
		u := &LLMUsage{Requests: len(calls)}
		runs := make(map[string]bool)
		for _, c := range calls {
			runs[c.Run] = true
			u.Input += c.Input
			u.Output += c.Output
			u.CacheRead += c.CacheRead
			u.CacheWrite += c.CacheWrite
			usd, ok := llm.Cost(llm.Usage{Model: c.Model, Input: c.Input, Output: c.Output, CacheRead: c.CacheRead, CacheWrite: c.CacheWrite})
			u.CostUSD += usd
			u.CostPartial = u.CostPartial || !ok
		}
		u.Runs = len(runs)
		r.LLM = u
	}
	return r, nil
}

func sorted(m map[string]*SubjectCount) []SubjectCount {
	out := make([]SubjectCount, 0, len(m))
	for _, sc := range m {
		out = append(out, *sc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// growth compares each container's average memory in the first and the
// last quarter of the period: robust to a GC sawtooth, and it needs no
// more than a handful of samples.
func growth(samples map[string][]history.MemorySample) []Growth {
	var out []Growth
	for name, s := range samples {
		if len(s) < minSamples {
			continue
		}
		q := len(s) / 4
		first, last := avg(s[:q]), avg(s[len(s)-q:])
		if first == 0 || float64(last) < float64(first)*growthRatio || last-first < growthBytes {
			continue
		}
		out = append(out, Growth{
			Container: name, FromBytes: first, ToBytes: last,
			Percent: (float64(last)/float64(first) - 1) * 100,
			Limit:   s[len(s)-1].Limit,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Percent > out[j].Percent })
	return out
}

func avg(s []history.MemorySample) uint64 {
	var sum uint64
	for _, m := range s {
		sum += m.Used
	}
	return sum / uint64(len(s))
}

func (b *Builder) render(title string, r *Report) string {
	loc := b.Location
	if loc == nil {
		loc = time.Local
	}
	var w strings.Builder
	fmt.Fprintf(&w, "*nodux %s*", strings.ToLower(title))
	if b.Host != "" {
		fmt.Fprintf(&w, " for %s", b.Host)
	}
	fmt.Fprintf(&w, ", %s – %s", r.From.In(loc).Format("Jan 2 15:04"), r.To.In(loc).Format("Jan 2 15:04 MST"))

	if r.Alerts == 0 {
		w.WriteString("\n*Alerts:* none.")
	} else {
		fmt.Fprintf(&w, "\n*Alerts:* %d (%d critical)", r.Alerts, r.Critical)
		if r.Incidents > 0 {
			fmt.Fprintf(&w, " in %d incidents", r.Incidents)
		}
		if r.Resolved > 0 {
			fmt.Fprintf(&w, ", %d resolutions", r.Resolved)
		}
	}
	if len(r.Containers) > 0 {
		w.WriteString("\n*Containers:*")
		for i, c := range r.Containers {
			if i == maxContainers {
				fmt.Fprintf(&w, "\n• and %d more", len(r.Containers)-maxContainers)
				break
			}
			fmt.Fprintf(&w, "\n• `%s`: %s", c.Subject, counts(c.ByDetector))
		}
	}
	if len(r.Host) > 0 {
		var parts []string
		for i, h := range r.Host {
			if i == maxHost {
				break
			}
			parts = append(parts, fmt.Sprintf("`%s`: %s", h.Subject, counts(h.ByDetector)))
		}
		fmt.Fprintf(&w, "\n*Host:* %s", strings.Join(parts, "; "))
	}
	if len(r.Flapping) > 0 {
		var parts []string
		for i, f := range r.Flapping {
			if i == maxFlapping {
				break
			}
			parts = append(parts, fmt.Sprintf("%s `%s` opened %d times", f.Detector, f.Subject, f.Episodes))
		}
		fmt.Fprintf(&w, "\n*Flapping:* %s", strings.Join(parts, "; "))
	}
	if len(r.Open) > 0 {
		var parts []string
		for i, o := range r.Open {
			if i == maxOpen {
				parts = append(parts, fmt.Sprintf("and %d more", len(r.Open)-maxOpen))
				break
			}
			parts = append(parts, fmt.Sprintf("%s `%s` (%s)", o.Detector, o.Subject, since(r.To, o.Since)))
		}
		fmt.Fprintf(&w, "\n*Still open:* %s", strings.Join(parts, ", "))
	}
	if len(r.Memory) > 0 {
		var parts []string
		for i, g := range r.Memory {
			if i == maxGrowth {
				break
			}
			s := fmt.Sprintf("`%s` %s → %s (+%.0f%%)", g.Container, detector.FormatBytes(g.FromBytes), detector.FormatBytes(g.ToBytes), g.Percent)
			if g.Limit > 0 {
				s += fmt.Sprintf(" of %s limit", detector.FormatBytes(g.Limit))
			}
			parts = append(parts, s)
		}
		fmt.Fprintf(&w, "\n*Memory growing:* %s", strings.Join(parts, ", "))
	}
	if u := r.LLM; u != nil {
		fmt.Fprintf(&w, "\n*LLM:* %d analyses in %d requests, %s input tokens (%s from cache), %s output",
			u.Runs, u.Requests, tokens(u.Input+u.CacheRead+u.CacheWrite), tokens(u.CacheRead), tokens(u.Output))
		switch {
		case u.CostPartial && u.CostUSD == 0:
		case u.CostPartial:
			fmt.Fprintf(&w, ", at least $%.2f", u.CostUSD)
		default:
			fmt.Fprintf(&w, ", about $%.2f", u.CostUSD)
		}
	}
	return w.String()
}

func counts(by map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range by {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = fmt.Sprintf("%s ×%d", e.k, e.v)
	}
	return strings.Join(parts, ", ")
}

func tokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1000:
		return fmt.Sprintf("%dk", (n+500)/1000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func since(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
