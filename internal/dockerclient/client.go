// Package dockerclient is a minimal Docker Engine API client over a
// unix socket. It only implements what nodux needs: listing containers,
// inspecting them, and fetching a tail of logs. Works with both Docker
// and Podman, since both expose a Docker-compatible REST API on a socket.
package dockerclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	socketPath string
	http       *http.Client
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
	}
}

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket %s: %w", c.socketPath, err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("docker API %s %s: status %d: %s", method, path, resp.StatusCode, string(body))
	}
	return resp, nil
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
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json")
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

// ContainerLogs returns up to tail of the last non-empty log lines
// (stdout+stderr interleaved, in the order the daemon emits them).
func (c *Client) ContainerLogs(ctx context.Context, id string, tail int, tty bool) ([]string, error) {
	path := fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true&tail=%d", id, tail)
	resp, err := c.do(ctx, http.MethodGet, path)
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
