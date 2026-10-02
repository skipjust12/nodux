// Package server exposes nodux's own state: /metrics in the Prometheus
// text format and /healthz for whoever watches nodux, and a small JSON
// API (status, silences) for the nodux status and nodux silence
// commands.
//
// The API changes what gets alerted, so it's only served on the unix
// socket, where file permissions decide who may use it. The TCP
// listener, meant for a Prometheus scraper, only gets /metrics and
// /healthz.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/skipjust12/nodux/internal/action"
	"github.com/skipjust12/nodux/internal/engine"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/silence"
)

// Engine is what the server reads from the engine.
type Engine interface {
	Healthy() bool
	LastPoll() time.Time
	Episodes() []engine.Episode
	AlertCounts() map[engine.AlertKey]uint64
}

// Receiver is an action that counts its deliveries.
type Receiver interface {
	Name() string
	Stats() action.DeliveryStats
}

// Source is everything the server reports on.
type Source struct {
	Engine       Engine
	Version      string
	Hostname     string
	Started      time.Time
	PollInterval time.Duration
	Silences     *silence.Store // nil: silences are off
	Receivers    []Receiver
	LLM          interface{ Budget() llm.Budget } // nil: the LLM layer is off
}

// Status is the GET /api/status response.
type Status struct {
	Host          string            `json:"host"`
	Version       string            `json:"version"`
	Started       time.Time         `json:"started"`
	DockerUp      bool              `json:"docker_up"`
	LastPoll      *time.Time        `json:"last_poll,omitempty"`
	Episodes      []engine.Episode  `json:"episodes"`
	Silences      []silence.Silence `json:"silences"`
	DeployWindows []silence.Window  `json:"deploy_windows"`
	Receivers     []ReceiverStatus  `json:"receivers"`
	LLM           *llm.Budget       `json:"llm,omitempty"`
}

type ReceiverStatus struct {
	Name string `json:"name"`
	action.DeliveryStats
}

// SilenceRequest is the POST /api/silences body.
type SilenceRequest struct {
	// Matcher in the command-line form: "api", "detector=memory,container=api".
	Matcher  string `json:"matcher"`
	Duration string `json:"duration"` // Go duration, or a number of days: "2d"
	Comment  string `json:"comment,omitempty"`
}

// Handler serves the endpoints; control adds the JSON API.
func Handler(src *Source, control bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", src.healthz)
	mux.HandleFunc("GET /metrics", src.metrics)
	if control {
		mux.HandleFunc("GET /api/status", src.status)
		mux.HandleFunc("GET /api/silences", src.listSilences)
		mux.HandleFunc("POST /api/silences", src.addSilence)
		mux.HandleFunc("DELETE /api/silences/{id}", src.removeSilence)
	}
	return mux
}

func (src *Source) healthz(w http.ResponseWriter, _ *http.Request) {
	if problem := src.unhealthy(); problem != "" {
		http.Error(w, problem, http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}

// unhealthy says what's wrong with nodux, "" if nothing: the Docker
// daemon is unreachable, or the poll loop has stopped making progress.
func (src *Source) unhealthy() string {
	if !src.Engine.Healthy() {
		return "docker daemon unreachable"
	}
	stale := 3*src.PollInterval + time.Minute
	if last := src.Engine.LastPoll(); time.Since(last) > stale {
		return fmt.Sprintf("no successful poll for %s", time.Since(last).Round(time.Second))
	}
	return ""
}

func (src *Source) Status() Status {
	st := Status{
		Host:          src.Hostname,
		Version:       src.Version,
		Started:       src.Started,
		DockerUp:      src.Engine.Healthy(),
		Episodes:      src.Engine.Episodes(),
		Silences:      []silence.Silence{},
		DeployWindows: []silence.Window{},
		Receivers:     []ReceiverStatus{},
	}
	if last := src.Engine.LastPoll(); !last.IsZero() {
		st.LastPoll = &last
	}
	if src.Silences != nil {
		st.Silences = src.Silences.List()
		st.DeployWindows = src.Silences.Windows()
	}
	for _, r := range src.Receivers {
		st.Receivers = append(st.Receivers, ReceiverStatus{Name: r.Name(), DeliveryStats: r.Stats()})
	}
	if src.LLM != nil {
		u := src.LLM.Budget()
		st.LLM = &u
	}
	return st
}

func (src *Source) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, src.Status())
}

func (src *Source) listSilences(w http.ResponseWriter, _ *http.Request) {
	if src.Silences == nil {
		writeJSON(w, http.StatusOK, []silence.Silence{})
		return
	}
	writeJSON(w, http.StatusOK, src.Silences.List())
}

func (src *Source) addSilence(w http.ResponseWriter, r *http.Request) {
	if src.Silences == nil {
		writeError(w, http.StatusNotImplemented, errors.New("silences are not enabled"))
		return
	}
	var req SilenceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad request body: %w", err))
		return
	}
	m, err := silence.ParseMatcher(req.Matcher)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	d, err := ParseDuration(req.Duration)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s, err := src.Silences.Add(m, d, req.Comment)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	slog.Info("silence added", "id", s.ID, "matcher", m.String(), "until", s.Until.Format(time.RFC3339), "comment", s.Comment)
	writeJSON(w, http.StatusCreated, s)
}

func (src *Source) removeSilence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if src.Silences == nil || !src.Silences.Remove(id) {
		writeError(w, http.StatusNotFound, fmt.Errorf("no silence %q", id))
		return
	}
	slog.Info("silence removed", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// ParseDuration is time.ParseDuration plus whole days ("2d").
func ParseDuration(s string) (time.Duration, error) {
	var days int
	if n, err := fmt.Sscanf(s, "%dd", &days); err == nil && n == 1 && fmt.Sprintf("%dd", days) == s {
		if days <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad duration %q (examples: 30m, 2h, 1d)", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return d, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, apiError{Error: err.Error()})
}

// ListenUnix creates the control socket, readable and writable by its
// owner and group only. A socket file left behind by a nodux that
// crashed is replaced; one that still answers is an error.
func ListenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve serves h on ln until ctx is cancelled.
func Serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
