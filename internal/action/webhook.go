package action

import (
	"encoding/json"
	"time"
)

const (
	FormatJSON  = "json"
	FormatSlack = "slack"
)

type WebhookConfig struct {
	// Name identifies the receiver in logs and metrics; "webhook" if empty.
	Name string
	URL  string
	// Format is "json" (the Record, as-is) or "slack" ({"text": ...},
	// also accepted by Mattermost, Rocket.Chat and Discord's /slack
	// endpoint).
	Format  string
	Headers map[string]string
	Timeout time.Duration
}

// NewWebhook POSTs notifications to an HTTP endpoint. In json format
// each alert is its own POST (the Record, as on the console); in slack
// format each notification is one message.
func NewWebhook(cfg WebhookConfig) *HTTPAction {
	if cfg.Format == "" {
		cfg.Format = FormatJSON
	}
	if cfg.Name == "" {
		cfg.Name = "webhook"
	}
	return newHTTPAction(cfg.Name, cfg.URL, cfg.Headers, cfg.Timeout, func(n Notification) ([][]byte, error) {
		return webhookPayloads(cfg.Format, n)
	})
}

// webhookPayloads is what to POST for a notification: one Slack
// message, or one JSON record per alert (or the digest record).
func webhookPayloads(format string, n Notification) ([][]byte, error) {
	if format == FormatSlack {
		b, err := json.Marshal(map[string]string{"text": slackNotification(n)})
		return [][]byte{b}, err
	}
	var out [][]byte
	if n.Digest != nil {
		b, err := json.Marshal(NewDigestRecord(n.Digest))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	for _, issue := range n.Alerts {
		b, err := json.Marshal(NewRecord(issue))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
