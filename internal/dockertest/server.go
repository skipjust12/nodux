// Package dockertest is a fake Docker Engine API served on a unix
// socket, for tests that exercise the real dockerclient end to end.
package dockertest

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/dockerclient"
)

type Server struct {
	SocketPath string

	mu         sync.Mutex
	down       bool
	containers map[string]*dockerclient.ContainerInspect
	order      []string
	logs       map[string][]string
	stats      map[string]*dockerclient.Stats
	statsCalls map[string]int
	top        map[string]*dockerclient.Top
	df         *dockerclient.DiskUsage
	// LogQueries gets the raw query of every logs request.
	LogQueries chan string
	// Each /events connection gets the next channel from streams; the
	// stream ends when that channel is closed.
	streams      chan chan dockerclient.Event
	EventQueries chan string // raw query of every /events request
}

func New(t *testing.T) *Server {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes, t.TempDir() can be longer.
	dir, err := os.MkdirTemp("", "nodux")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	s := &Server{
		SocketPath:   filepath.Join(dir, "docker.sock"),
		containers:   make(map[string]*dockerclient.ContainerInspect),
		logs:         make(map[string][]string),
		stats:        make(map[string]*dockerclient.Stats),
		statsCalls:   make(map[string]int),
		top:          make(map[string]*dockerclient.Top),
		LogQueries:   make(chan string, 64),
		streams:      make(chan chan dockerclient.Event, 16),
		EventQueries: make(chan string, 16),
	}
	ln, err := net.Listen("unix", s.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s
}

// AddContainer registers (or replaces) a container.
func (s *Server) AddContainer(c *dockerclient.ContainerInspect, logs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.containers[c.ID]; !ok {
		s.order = append(s.order, c.ID)
	}
	s.containers[c.ID] = c
	s.logs[c.ID] = logs
}

// SetStats sets what /containers/{id}/stats returns.
func (s *Server) SetStats(id string, st *dockerclient.Stats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats[id] = st
}

// SetTop sets what /containers/{id}/top returns.
func (s *Server) SetTop(id string, top *dockerclient.Top) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.top[id] = top
}

// SetDiskUsage sets what /system/df returns.
func (s *Server) SetDiskUsage(df *dockerclient.DiskUsage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.df = df
}

// StatsCallCount returns how many times stats were fetched for id.
func (s *Server) StatsCallCount(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statsCalls[id]
}

func (s *Server) RemoveContainer(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.containers, id)
	for i, cid := range s.order {
		if cid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// NewStream queues the event stream for the next /events connection.
func (s *Server) NewStream() chan<- dockerclient.Event {
	ch := make(chan dockerclient.Event, 16)
	s.streams <- ch
	return ch
}

// SetDown makes every endpoint fail with 500, like a daemon that's
// wedged or restarting.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		http.Error(w, `{"message":"daemon unavailable"}`, http.StatusInternalServerError)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/_ping":
		w.Write([]byte("OK"))
	case path == "/containers/json":
		s.list(w)
	case path == "/events":
		s.events(w, r)
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		s.inspect(w, strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json"))
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/stats"):
		s.containerStats(w, strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/stats"))
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/logs"):
		select {
		case s.LogQueries <- r.URL.RawQuery:
		default:
		}
		tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
		s.containerLogs(w, strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/logs"), tail)
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/top"):
		s.containerTop(w, strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/top"))
	case path == "/system/df":
		s.mu.Lock()
		df := s.df
		s.mu.Unlock()
		if df == nil {
			df = &dockerclient.DiskUsage{}
		}
		json.NewEncoder(w).Encode(df)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) list(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []dockerclient.ContainerSummary{}
	for _, id := range s.order {
		c := s.containers[id]
		var created int64
		if t, err := time.Parse(time.RFC3339Nano, c.Created); err == nil {
			created = t.Unix()
		}
		out = append(out, dockerclient.ContainerSummary{
			ID: c.ID, Names: []string{c.Name}, Image: c.Config.Image, ImageID: c.Image, Created: created,
			State: c.State.Status, Status: c.State.Status, Labels: c.Config.Labels,
		})
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) inspect(w http.ResponseWriter, id string) {
	s.mu.Lock()
	c, ok := s.containers[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(c)
}

func (s *Server) containerStats(w http.ResponseWriter, id string) {
	s.mu.Lock()
	s.statsCalls[id]++
	st, ok := s.stats[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(st)
}

func (s *Server) containerTop(w http.ResponseWriter, id string) {
	s.mu.Lock()
	top, ok := s.top[id]
	_, exists := s.containers[id]
	s.mu.Unlock()
	if !exists {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		return
	}
	if !ok {
		top = &dockerclient.Top{Titles: []string{"PID", "CMD"}}
	}
	json.NewEncoder(w).Encode(top)
}

// containerLogs writes the multiplexed (non-TTY) log format.
func (s *Server) containerLogs(w http.ResponseWriter, id string, tail int) {
	s.mu.Lock()
	lines, ok := s.logs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		return
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	for _, line := range lines {
		payload := []byte(line + "\n")
		header := make([]byte, 8)
		header[0] = 1 // stdout
		binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
		w.Write(header)
		w.Write(payload)
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	select {
	case s.EventQueries <- r.URL.RawQuery:
	default:
	}
	var ch chan dockerclient.Event
	select {
	case ch = <-s.streams:
	case <-r.Context().Done():
		return
	}
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	enc := json.NewEncoder(w)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			enc.Encode(ev)
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}
