package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	ntfyMaxMessage = 3800 // ntfy turns longer messages into attachments
	ntfyLogLines   = 10
	ntfyLineMax    = 300
)

type NtfyConfig struct {
	Name string
	// URL is the topic URL, e.g. https://ntfy.sh/mytopic. On ntfy.sh the
	// topic name is effectively the password; keep it in an environment
	// variable.
	URL string
	// Token is an access token for a protected topic (Authorization:
	// Bearer). user:pass@ in the URL works too.
	Token   string
	Timeout time.Duration
}

// NewNtfy publishes each alert to an ntfy topic. Critical alerts get
// the highest priority (on phones that can break through do-not-disturb),
// warnings the default one, resolutions a low one.
func NewNtfy(cfg NtfyConfig) (*HTTPAction, error) {
	base, topic, err := splitNtfyURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		cfg.Name = "ntfy"
	}
	return newHTTPAction(cfg.Name, cfg.URL, cfg.Timeout, func(ctx context.Context, issue detector.Issue) (*http.Request, error) {
		body, err := json.Marshal(ntfyMessage(topic, issue))
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
		}
		return req, nil
	}), nil
}

// splitNtfyURL turns https://ntfy.example.com/sub/topic into the server
// root to publish JSON to (https://ntfy.example.com/sub) and the topic.
func splitNtfyURL(raw string) (base, topic string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("ntfy url must be http(s)://server/topic")
	}
	path := strings.TrimRight(u.Path, "/")
	i := strings.LastIndex(path, "/")
	if i < 0 || path[i+1:] == "" {
		return "", "", fmt.Errorf("ntfy url must end in a topic name")
	}
	topic = path[i+1:]
	u.Path = path[:i]
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), topic, nil
}

type ntfyPublish struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Priority int      `json:"priority"`
	Tags     []string `json:"tags,omitempty"`
}

func ntfyMessage(topic string, issue detector.Issue) ntfyPublish {
	title := headline(issue)
	if s := subject(issue); s != "" {
		title += " " + s
	}
	if issue.Host != "" {
		title += " on " + issue.Host
	}

	m := ntfyPublish{Topic: topic, Title: title, Priority: 3, Tags: []string{"warning"}}
	switch {
	case issue.Resolved:
		m.Priority, m.Tags = 2, []string{"white_check_mark"}
	case issue.Severity == detector.SeverityCritical:
		m.Priority, m.Tags = 5, []string{"rotating_light"}
	}

	text := detector.Truncate(issue.Message, 1500)
	if issue.Analysis != "" {
		text += "\n\n" + detector.Truncate(issue.Analysis, 600)
	}
	lines := lastLines(issue.Logs, ntfyLogLines, ntfyLineMax)
	for len(lines) > 0 {
		block := "\n\n" + strings.Join(lines, "\n")
		if len(text)+len(block) <= ntfyMaxMessage {
			text += block
			break
		}
		lines = lines[1:]
	}
	m.Message = text
	return m
}
