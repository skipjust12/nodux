package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/skipjust12/nodux/internal/silence"
)

// DefaultSocket is where the daemon listens unless configured otherwise.
const DefaultSocket = "/run/nodux/nodux.sock"

// Client talks to a running nodux over its control socket.
type Client struct {
	socket string
	http   *http.Client
}

func NewClient(socket string) *Client {
	return &Client{
		socket: socket,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (c *Client) Status(ctx context.Context) (*Status, error) {
	var st Status
	return &st, c.do(ctx, http.MethodGet, "/api/status", nil, &st)
}

func (c *Client) Silences(ctx context.Context) ([]silence.Silence, error) {
	var out []silence.Silence
	return out, c.do(ctx, http.MethodGet, "/api/silences", nil, &out)
}

func (c *Client) AddSilence(ctx context.Context, req SilenceRequest) (*silence.Silence, error) {
	var s silence.Silence
	return &s, c.do(ctx, http.MethodPost, "/api/silences", req, &s)
}

func (c *Client) RemoveSilence(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/silences/"+url.PathEscape(id), nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://nodux"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach nodux at %s (is it running? see --socket): %w", c.socket, unwrapURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e apiError
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("nodux: status %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func unwrapURL(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}
