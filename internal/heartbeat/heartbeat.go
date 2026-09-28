// Package heartbeat pings a dead man's switch (healthchecks.io, Uptime
// Kuma push monitors, Better Stack heartbeats, ...) while nodux is
// working, so that nodux itself dying, or losing the Docker daemon, is
// noticed by something outside the box.
package heartbeat

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/skipjust12/nodux/internal/redact"
)

type Heartbeat struct {
	url      string
	interval time.Duration
	healthy  func() bool
	client   *http.Client
}

// New returns a heartbeat that GETs url every interval, as long as
// healthy() says monitoring works.
func New(url string, interval time.Duration, healthy func() bool) *Heartbeat {
	return &Heartbeat{
		url:      url,
		interval: interval,
		healthy:  healthy,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Run pings until ctx is cancelled.
func (h *Heartbeat) Run(ctx context.Context) {
	t := time.NewTicker(h.interval)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !h.healthy() {
			// Stay silent: the monitor will alert on the missed pings.
			slog.Debug("heartbeat skipped, docker daemon unreachable")
			continue
		}
		if err := h.ping(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			// Log the first failure of a streak, not every one.
			if !failing {
				slog.Warn("heartbeat ping failed", "url", redact.URL(h.url), "error", err)
			}
			failing = true
			continue
		}
		if failing {
			slog.Info("heartbeat ping recovered", "url", redact.URL(h.url))
		}
		failing = false
	}
}

func (h *Heartbeat) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return redact.Err(err)
	}
	req.Header.Set("User-Agent", "nodux")
	resp, err := h.client.Do(req)
	if err != nil {
		return redact.Err(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
