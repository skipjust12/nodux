// Package silence keeps the silences and maintenance windows that stop
// alerts from reaching receivers. A silence is set by hand (nodux
// silence api 30m) and matches alerts by detector, container, compose
// project or resource. A deploy window is opened automatically when the
// event stream shows a container being created, stopped or removed, and
// covers that container and the rest of its compose project for a grace
// period after the last such event. Deploy windows only hold back
// ongoing problems (a probe failing during a recreate); a crash or an
// OOM kill is reported even mid-deploy.
//
// Silenced alerts are still tracked and logged to stdout; they just
// aren't sent anywhere. With a state file, silences and windows survive
// a restart of nodux.
package silence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// Matcher selects alerts. Every non-empty field must match; the values
// are shell-style globs (api-*). Target matches either the container
// name or the resource, which is what a bare word on the command line
// means. A matcher with every field empty matches nothing; use Target
// "*" to silence everything.
type Matcher struct {
	Target    string `json:"target,omitempty"`
	Detector  string `json:"detector,omitempty"`
	Container string `json:"container,omitempty"`
	Project   string `json:"project,omitempty"`
	Resource  string `json:"resource,omitempty"`
}

// Subject is what an alert is about, as far as silences care.
type Subject struct {
	Detector  string
	Container string
	Project   string
	Resource  string
	// OneOff marks an alert about something that happened (a crash, an
	// OOM kill) rather than an ongoing state. Deploy windows don't apply
	// to those: a deploy doesn't make a container crash, and a one-off
	// alert held back is lost, while an episode held back goes out when
	// the window closes if it's still open.
	OneOff bool
}

type Silence struct {
	ID      string    `json:"id"`
	Matcher Matcher   `json:"matcher"`
	Comment string    `json:"comment,omitempty"`
	Created time.Time `json:"created"`
	Until   time.Time `json:"until"`
}

// Window is an automatic deploy window.
type Window struct {
	// Scope is "container" or "project".
	Scope string    `json:"scope"`
	Name  string    `json:"name"`
	Until time.Time `json:"until"`
}

type Store struct {
	mu       sync.Mutex
	silences map[string]*Silence
	windows  map[windowKey]time.Time
	now      func() time.Time
}

type windowKey struct{ scope, name string }

func New() *Store {
	return &Store{
		silences: make(map[string]*Silence),
		windows:  make(map[windowKey]time.Time),
		now:      time.Now,
	}
}

// ParseMatcher reads the command-line form: a bare target ("api",
// "api-*", "/var/lib/docker"), "*" or "all" for everything, or
// comma-separated key=value pairs with keys detector, container,
// project, resource and target.
func ParseMatcher(s string) (Matcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Matcher{}, fmt.Errorf("empty matcher")
	}
	if s == "all" {
		s = "*"
	}
	var m Matcher
	if !strings.Contains(s, "=") {
		if strings.Contains(s, ",") {
			return Matcher{}, fmt.Errorf("bad matcher %q: use key=value pairs to combine conditions", s)
		}
		m.Target = s
		return m, m.Validate()
	}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || v == "" {
			return Matcher{}, fmt.Errorf("bad matcher %q: want key=value", part)
		}
		switch k {
		case "target":
			m.Target = v
		case "detector":
			m.Detector = v
		case "container":
			m.Container = v
		case "project":
			m.Project = v
		case "resource":
			m.Resource = v
		default:
			return Matcher{}, fmt.Errorf("bad matcher key %q: want detector, container, project, resource or target", k)
		}
	}
	return m, m.Validate()
}

// Validate checks that the matcher selects something and its globs
// compile.
func (m Matcher) Validate() error {
	fields := []string{m.Target, m.Detector, m.Container, m.Project, m.Resource}
	empty := true
	for _, f := range fields {
		if f == "" {
			continue
		}
		empty = false
		if _, err := path.Match(f, ""); err != nil {
			return fmt.Errorf("bad pattern %q: %w", f, err)
		}
	}
	if empty {
		return fmt.Errorf("empty matcher")
	}
	return nil
}

func (m Matcher) String() string {
	var parts []string
	for _, kv := range [][2]string{
		{"target", m.Target}, {"detector", m.Detector}, {"container", m.Container},
		{"project", m.Project}, {"resource", m.Resource},
	} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	if len(parts) == 1 && m.Target != "" {
		return m.Target
	}
	return strings.Join(parts, ",")
}

// Matches reports whether the matcher selects the subject.
func (m Matcher) Matches(s Subject) bool {
	if m.Validate() != nil {
		return false
	}
	if m.Target != "" && !glob(m.Target, s.Container) && !glob(m.Target, s.Resource) {
		return false
	}
	return (m.Detector == "" || glob(m.Detector, s.Detector)) &&
		(m.Container == "" || glob(m.Container, s.Container)) &&
		(m.Project == "" || glob(m.Project, s.Project)) &&
		(m.Resource == "" || glob(m.Resource, s.Resource))
}

// glob matches s against pattern; "*" matches anything, including
// paths and the empty string.
func glob(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if s == "" {
		return false
	}
	ok, _ := path.Match(pattern, s)
	return ok
}

// Add creates a silence lasting d.
func (st *Store) Add(m Matcher, d time.Duration, comment string) (Silence, error) {
	if err := m.Validate(); err != nil {
		return Silence{}, err
	}
	if d <= 0 {
		return Silence{}, fmt.Errorf("duration must be positive")
	}
	var b [4]byte
	rand.Read(b[:])
	now := st.now()
	s := &Silence{ID: hex.EncodeToString(b[:]), Matcher: m, Comment: comment, Created: now, Until: now.Add(d)}

	st.mu.Lock()
	defer st.mu.Unlock()
	st.silences[s.ID] = s
	return *s, nil
}

// Remove ends a silence early. It reports whether one was found.
func (st *Store) Remove(id string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.silences[id]; !ok {
		return false
	}
	delete(st.silences, id)
	return true
}

// Deploy opens (or extends) the deploy window for a container and its
// compose project.
func (st *Store) Deploy(container, project string, until time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, k := range []windowKey{{"container", container}, {"project", project}} {
		if k.name != "" && until.After(st.windows[k]) {
			st.windows[k] = until
		}
	}
}

// List returns the active silences, soonest to expire first.
func (st *Store) List() []Silence {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneLocked()
	out := make([]Silence, 0, len(st.silences))
	for _, s := range st.silences {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Until.Equal(out[j].Until) {
			return out[i].Until.Before(out[j].Until)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Windows returns the open deploy windows.
func (st *Store) Windows() []Window {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneLocked()
	out := make([]Window, 0, len(st.windows))
	for k, until := range st.windows {
		out = append(out, Window{Scope: k.scope, Name: k.name, Until: until})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Silenced reports whether an alert about s is silenced, and why.
func (st *Store) Silenced(s Subject) (reason string, ok bool) {
	if st == nil {
		return "", false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneLocked()
	if s.Container != "" && !s.OneOff {
		if _, ok := st.windows[windowKey{"container", s.Container}]; ok {
			return "deploy of " + s.Container, true
		}
	}
	if s.Project != "" && !s.OneOff {
		if _, ok := st.windows[windowKey{"project", s.Project}]; ok {
			return "deploy of compose project " + s.Project, true
		}
	}
	for _, sil := range st.silences {
		if sil.Matcher.Matches(s) {
			return "silence " + sil.ID, true
		}
	}
	return "", false
}

func (st *Store) pruneLocked() {
	now := st.now()
	for id, s := range st.silences {
		if !now.Before(s.Until) {
			delete(st.silences, id)
		}
	}
	for k, until := range st.windows {
		if !now.Before(until) {
			delete(st.windows, k)
		}
	}
}

type saved struct {
	Silences []Silence `json:"silences,omitempty"`
	Windows  []Window  `json:"windows,omitempty"`
}

// SaveState returns the active silences and deploy windows.
func (st *Store) SaveState() ([]byte, error) {
	return json.Marshal(saved{Silences: st.List(), Windows: st.Windows()})
}

// LoadState restores saved silences and windows; ones that ended in the
// meantime are dropped.
func (st *Store) LoadState(data []byte) error {
	var sv saved
	if err := json.Unmarshal(data, &sv); err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range sv.Silences {
		if s.ID != "" && s.Matcher.Validate() == nil {
			s := s
			st.silences[s.ID] = &s
		}
	}
	for _, w := range sv.Windows {
		k := windowKey{w.Scope, w.Name}
		if (w.Scope == "container" || w.Scope == "project") && w.Name != "" && w.Until.After(st.windows[k]) {
			st.windows[k] = w.Until
		}
	}
	st.pruneLocked()
	return nil
}
