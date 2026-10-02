package action

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	ntfyMaxMessage = 3800 // ntfy turns longer messages into attachments
	ntfyLogLines   = 10
	ntfyLineMax    = 300
	ntfyItemMax    = 300
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

// NewNtfy publishes each notification to an ntfy topic. Critical alerts
// get the highest priority (on phones that can break through
// do-not-disturb), warnings the default one, resolutions and digests a
// low one.
func NewNtfy(cfg NtfyConfig) (*HTTPAction, error) {
	base, topic, err := splitNtfyURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		cfg.Name = "ntfy"
	}
	var headers map[string]string
	if cfg.Token != "" {
		headers = map[string]string{"Authorization": "Bearer " + cfg.Token}
	}
	return newHTTPAction(cfg.Name, base, headers, cfg.Timeout, func(n Notification) ([][]byte, error) {
		b, err := json.Marshal(ntfyMessage(topic, n))
		return [][]byte{b}, err
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

func ntfyMessage(topic string, n Notification) ntfyPublish {
	m := ntfyPublish{Topic: topic}
	if n.Digest != nil {
		m.Title = n.Digest.Title
		if n.Digest.Host != "" {
			m.Title += " for " + n.Digest.Host
		}
		m.Message = detector.Truncate(n.Digest.Text, ntfyMaxMessage)
		m.Priority, m.Tags = 2, []string{"bar_chart"}
		return m
	}

	label, nFiring, nResolved := batchLabel(n.Alerts)
	switch {
	case nFiring == 0:
		m.Priority, m.Tags = 2, []string{"white_check_mark"}
	case label == "CRITICAL":
		m.Priority, m.Tags = 5, []string{"rotating_light"}
	default:
		m.Priority, m.Tags = 3, []string{"warning"}
	}

	var text string
	if len(n.Alerts) == 1 {
		issue := n.Alerts[0]
		m.Title = headline(issue)
		if s := subject(issue); s != "" {
			m.Title += " " + s
		}
		if issue.Host != "" {
			m.Title += " on " + issue.Host
		}
		text = detector.Truncate(issue.Message, 1500)
		if issue.Analysis != "" {
			text += "\n\n" + detector.Truncate(issue.Analysis, 600)
		}
	} else {
		m.Title = fmt.Sprintf("[%s] incident #%d", label, n.IncidentID)
		if n.Update {
			m.Title += " (update)"
		}
		if host := n.Alerts[0].Host; host != "" {
			m.Title += " on " + host
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d new, %d resolved", nFiring, nResolved)
		if n.Summary != "" {
			b.WriteString("\n\n" + detector.Truncate(n.Summary, 600))
		}
		b.WriteString("\n")
		for _, issue := range n.Alerts {
			item := issue.Detector
			if issue.Resolved {
				item = "resolved " + item
			}
			if s := subject(issue); s != "" {
				item += " " + s
			}
			b.WriteString("\n• " + detector.Truncate(item+": "+issue.Message, ntfyItemMax))
		}
		text = detector.Truncate(b.String(), ntfyMaxMessage-200)
	}

	lines := lastLines(firstLogs(n.Alerts), ntfyLogLines, ntfyLineMax)
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
