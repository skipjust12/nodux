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
	"strings"
	"sync"
	"testing"

	"github.com/skipjust12/nodux/internal/dockerclient"
)

type Server struct {
	SocketPath string

	mu         sync.Mutex
	containers map[string]*dockerclient.ContainerInspect
	order      []string
	logs       map[string][]string
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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/logs"):
		s.containerLogs(w, strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/logs"))
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
		out = append(out, dockerclient.ContainerSummary{ID: c.ID, Names: []string{c.Name}, State: c.State.Status})
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

// containerLogs writes the multiplexed (non-TTY) log format.
func (s *Server) containerLogs(w http.ResponseWriter, id string) {
	s.mu.Lock()
	lines, ok := s.logs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		return
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
