// Package dockerclient is a minimal Docker Engine API client over a
// unix socket. It only implements what nodux needs, all of it read-only:
// listing and inspecting containers, stats, processes, logs, disk usage
// and the event stream. Works with both Docker and Podman, since both
// expose a Docker-compatible REST API on a socket.
package dockerclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	socketPath string
	http       *http.Client
	// stream has no overall timeout: /events is a long-lived response
	// that's only ever ended by ctx cancellation or the daemon.
	stream *http.Client
}

func New(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		socketPath: socketPath,
		http: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		stream: &http.Client{Transport: transport},
	}
}

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	return c.doWith(ctx, c.http, method, path)
}

func (c *Client) doWith(ctx context.Context, hc *http.Client, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket %s: %w", c.socketPath, err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return resp, nil
}

// APIError is a non-2xx response from the daemon.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("docker API %s %s: status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// IsGone reports whether err means the container no longer exists (404)
// or is being removed (409), which is routine for docker run --rm.
func IsGone(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusConflict
}

// Ping checks whether the daemon is reachable. Used as an explicit
// connectivity check before polling, so "daemon unreachable" can be
// told apart from other errors.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/_ping")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ListContainers returns all containers, including stopped ones.
func (c *Client) ListContainers(ctx context.Context) ([]ContainerSummary, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/json?all=true")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out []ContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode container list: %w", err)
	}
	return out, nil
}

// InspectContainer returns detailed state for a single container.
func (c *Client) InspectContainer(ctx context.Context, id string) (*ContainerInspect, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out ContainerInspect
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode container inspect %s: %w", id, err)
	}
	return &out, nil
}

// ContainerStats returns a single stats sample. one-shot skips the
// daemon's wait for a second sample (only needed for CPU percentages),
// which makes this a ~30ms call instead of ~1-2s.
func (c *Client) ContainerStats(ctx context.Context, id string) (*Stats, error) {
	return c.stats(ctx, id, "stream=false&one-shot=true")
}

// ContainerStatsSampled returns stats with a previous sample to compare
// with, so CPUPercent works. The daemon waits for that second sample,
// which takes a second or two.
func (c *Client) ContainerStatsSampled(ctx context.Context, id string) (*Stats, error) {
	return c.stats(ctx, id, "stream=false")
}

func (c *Client) stats(ctx context.Context, id, query string) (*Stats, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/stats?"+query)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out Stats
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode container stats %s: %w", id, err)
	}
	return &out, nil
}

// ContainerLogs returns up to tail of the last non-empty log lines
// (stdout+stderr interleaved, in the order the daemon emits them).
func (c *Client) ContainerLogs(ctx context.Context, id string, tail int, tty bool) ([]string, error) {
	return c.ContainerLogsRange(ctx, id, LogOptions{Tail: tail, TTY: tty})
}

// LogOptions narrows a log fetch. Zero values mean no limit.
type LogOptions struct {
	Since, Until time.Time
	Tail         int
	TTY          bool // the container has a TTY: logs aren't multiplexed
	// Timestamps prefixes each line with the time the daemon logged it
	// (RFC 3339, nanoseconds).
	Timestamps bool
}

// ContainerLogsRange returns the non-empty log lines between Since and
// Until, at most the last Tail of them.
func (c *Client) ContainerLogsRange(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	q := url.Values{"stdout": {"true"}, "stderr": {"true"}}
	if opts.Tail > 0 {
		q.Set("tail", strconv.Itoa(opts.Tail))
	}
	if !opts.Since.IsZero() {
		q.Set("since", unixTime(opts.Since))
	}
	if !opts.Until.IsZero() {
		q.Set("until", unixTime(opts.Until))
	}
	if opts.Timestamps {
		q.Set("timestamps", "true")
	}
	tty := opts.TTY
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs?"+q.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var text string
	if tty {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read logs %s: %w", id, err)
		}
		text = string(raw)
	} else {
		text, err = demuxLogs(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("demux logs %s: %w", id, err)
		}
	}

	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// Events follows the daemon's container event stream, calling fn for
// every event of the given actions, and blocks until ctx is cancelled or
// the stream breaks. If since is non-zero, the daemon first replays
// buffered events from that point on, which lets the caller resume after
// a reconnect without a gap.
func (c *Client) Events(ctx context.Context, since time.Time, actions []string, fn func(Event)) error {
	filters, err := json.Marshal(map[string][]string{
		"type":  {"container"},
		"event": actions,
	})
	if err != nil {
		return err
	}
	q := url.Values{"filters": {string(filters)}}
	if !since.IsZero() {
		q.Set("since", unixTime(since))
	}

	resp, err := c.doWith(ctx, c.stream, http.MethodGet, "/events?"+q.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == io.EOF {
				return fmt.Errorf("event stream closed by daemon")
			}
			return fmt.Errorf("decode event: %w", err)
		}
		fn(ev)
	}
}

// ContainerTop lists the processes running in a container.
func (c *Client) ContainerTop(ctx context.Context, id string) (*Top, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/top")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out Top
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode container top %s: %w", id, err)
	}
	return &out, nil
}

// DiskUsage is docker system df: what images, containers, volumes and
// the build cache take up. It can take a while on a big host, since the
// daemon walks volume directories.
func (c *Client) DiskUsage(ctx context.Context) (*DiskUsage, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := c.doWith(ctx, c.stream, http.MethodGet, "/system/df")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out DiskUsage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode system df: %w", err)
	}
	return &out, nil
}

// unixTime formats t the way the API takes since/until: seconds with a
// nanosecond fraction.
func unixTime(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10) + "." + fmt.Sprintf("%09d", t.Nanosecond())
}

// demuxLogs parses Docker's multiplexed log stream format: each frame
// is an 8-byte header (1 stream-type byte, 3 zero bytes, 4 big-endian
// length bytes) followed by a payload of that length.
func demuxLogs(r io.Reader) (string, error) {
	var buf bytes.Buffer
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return "", err
		}
		size := binary.BigEndian.Uint32(header[4:8])
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return "", err
		}
		buf.Write(payload)
	}
	return buf.String(), nil
}
