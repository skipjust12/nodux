// Package incident groups alerts that are probably about the same
// problem, so they go out as one message (with one LLM summary) instead
// of one each. Grouping is deterministic: alerts join an incident when
// it's recent and they share something with it:
//
//   - the same container;
//   - the same compose project (the database crashes, then the API that
//     depends on it);
//   - the host: a host-level alert (disk, memory, CPU, the Docker daemon)
//     is a plausible cause of anything failing at the same time, so it
//     pulls container alerts into its incident and joins theirs.
//
// An incident takes new alerts while its last alert is less than Window
// old. Alerts are held for GroupWait before they're sent, so a burst
// (OOM, exit, crash loop, host memory) arrives as one message; later
// alerts of the same incident go out as updates.
package incident

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const maxEarlier = 20

type Config struct {
	// Enabled off sends every alert on its own, right away.
	Enabled   bool
	GroupWait time.Duration
	Window    time.Duration
}

// Batch is one message's worth of alerts.
type Batch struct {
	IncidentID int64 // 0 = not part of an incident
	// Update is set when earlier alerts of the incident were already sent.
	Update bool
	Alerts []detector.Issue
	// Earlier are the incident's firing alerts that were already sent
	// (without logs), and PrevSummary the analysis that went with them:
	// context for analyzing an update.
	Earlier     []detector.Issue
	PrevSummary string
}

// Firing reports whether the batch has anything but resolutions.
func (b *Batch) Firing() bool {
	for _, a := range b.Alerts {
		if !a.Resolved {
			return true
		}
	}
	return false
}

type Grouper struct {
	cfg Config
	now func() time.Time

	mu     sync.Mutex
	nextID int64
	open   []*incident
	// byKey maps an open episode to its incident, so its resolution can
	// be sent with (or as an update to) the incident it started in.
	byKey map[string]int64
	ready []Batch
}

type incident struct {
	id       int64
	subjects map[string]bool
	hasHost  bool
	last     time.Time // last firing alert
	notified bool
	pending  []detector.Issue
	due      time.Time // zero = nothing pending
	earlier  []detector.Issue
	summary  string
}

func New(cfg Config) *Grouper {
	return &Grouper{cfg: cfg, now: time.Now, byKey: make(map[string]int64)}
}

// Add files an alert under its incident and sets issue.IncidentID.
func (g *Grouper) Add(issue detector.Issue) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	if !g.cfg.Enabled {
		g.ready = append(g.ready, Batch{Alerts: []detector.Issue{issue}})
		return
	}
	g.expire(now)

	if issue.Resolved {
		id := g.byKey[issue.Key]
		if issue.Key != "" {
			delete(g.byKey, issue.Key)
		}
		issue.IncidentID = id
		if inc := g.find(id); inc != nil {
			g.enqueue(inc, issue, now)
			return
		}
		g.ready = append(g.ready, Batch{IncidentID: id, Update: id != 0, Alerts: []detector.Issue{issue}})
		return
	}

	subjects, isHost := subjectsOf(issue)
	var inc *incident
	for _, cand := range g.open {
		if (inc == nil || cand.last.After(inc.last)) && matches(cand, subjects, isHost) {
			inc = cand
		}
	}
	if inc == nil {
		g.nextID++
		inc = &incident{id: g.nextID, subjects: make(map[string]bool)}
		g.open = append(g.open, inc)
	}
	inc.last = now
	for s := range subjects {
		inc.subjects[s] = true
	}
	inc.hasHost = inc.hasHost || isHost
	issue.IncidentID = inc.id
	if issue.Key != "" {
		g.byKey[issue.Key] = inc.id
	}
	g.enqueue(inc, issue, now)
}

func (g *Grouper) enqueue(inc *incident, issue detector.Issue, now time.Time) {
	inc.pending = append(inc.pending, issue)
	if inc.due.IsZero() {
		inc.due = now.Add(g.cfg.GroupWait)
	}
}

func (g *Grouper) find(id int64) *incident {
	if id == 0 {
		return nil
	}
	for _, inc := range g.open {
		if inc.id == id {
			return inc
		}
	}
	return nil
}

// expire closes incidents that have been quiet for a whole window and
// have nothing left to send.
func (g *Grouper) expire(now time.Time) {
	kept := g.open[:0]
	for _, inc := range g.open {
		if inc.due.IsZero() && now.Sub(inc.last) >= g.cfg.Window {
			continue
		}
		kept = append(kept, inc)
	}
	clear(g.open[len(kept):])
	g.open = kept
}

func subjectsOf(issue detector.Issue) (subjects map[string]bool, isHost bool) {
	c := issue.Container
	if c.Name == "" {
		return nil, true
	}
	subjects = map[string]bool{"container:" + c.Name: true}
	if p := c.Labels[detector.LabelComposeProject]; p != "" {
		subjects["project:"+p] = true
	}
	return subjects, false
}

func matches(inc *incident, subjects map[string]bool, isHost bool) bool {
	if isHost || inc.hasHost {
		return true
	}
	for s := range subjects {
		if inc.subjects[s] {
			return true
		}
	}
	return false
}

// Next is when the next batch is due; zero if nothing is pending.
func (g *Grouper) Next() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.ready) > 0 {
		return g.now()
	}
	var next time.Time
	for _, inc := range g.open {
		if !inc.due.IsZero() && (next.IsZero() || inc.due.Before(next)) {
			next = inc.due
		}
	}
	return next
}

// Due returns the batches that are ready to go at now.
func (g *Grouper) Due(now time.Time) []Batch {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.take(func(inc *incident) bool { return !inc.due.After(now) })
}

// Flush returns everything still pending, due or not (shutdown).
func (g *Grouper) Flush() []Batch {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.take(func(*incident) bool { return true })
}

func (g *Grouper) take(due func(*incident) bool) []Batch {
	out := g.ready
	g.ready = nil

	var flush []*incident
	for _, inc := range g.open {
		if !inc.due.IsZero() && due(inc) {
			flush = append(flush, inc)
		}
	}
	sort.Slice(flush, func(i, j int) bool { return flush[i].due.Before(flush[j].due) })
	for _, inc := range flush {
		b := Batch{
			IncidentID:  inc.id,
			Update:      inc.notified,
			Alerts:      inc.pending,
			Earlier:     append([]detector.Issue(nil), inc.earlier...),
			PrevSummary: inc.summary,
		}
		for _, a := range inc.pending {
			if !a.Resolved {
				a.Logs = nil
				inc.earlier = append(inc.earlier, a)
			}
		}
		if n := len(inc.earlier); n > maxEarlier {
			inc.earlier = append([]detector.Issue(nil), inc.earlier[n-maxEarlier:]...)
		}
		inc.pending, inc.due, inc.notified = nil, time.Time{}, true
		out = append(out, b)
	}
	return out
}

// SetSummary records the analysis sent for an incident, for the
// context of its next update.
func (g *Grouper) SetSummary(id int64, summary string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if inc := g.find(id); inc != nil && summary != "" {
		inc.summary = summary
	}
}

type saved struct {
	NextID int64            `json:"next_id"`
	ByKey  map[string]int64 `json:"by_key,omitempty"`
}

// SaveState keeps the incident counter and which incident each open
// episode belongs to.
func (g *Grouper) SaveState() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return json.Marshal(saved{NextID: g.nextID, ByKey: g.byKey})
}

func (g *Grouper) LoadState(data []byte) error {
	var s saved
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nextID = max(g.nextID, s.NextID)
	for k, v := range s.ByKey {
		g.byKey[k] = v
	}
	return nil
}

// Name makes the grouper look like any other piece of saved state.
func (g *Grouper) Name() string { return "incidents" }
