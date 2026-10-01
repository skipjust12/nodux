package action

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
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

// NewWebhook POSTs each alert to an HTTP endpoint as JSON.
func NewWebhook(cfg WebhookConfig) *HTTPAction {
	if cfg.Format == "" {
		cfg.Format = FormatJSON
	}
	if cfg.Name == "" {
		cfg.Name = "webhook"
	}
	return newHTTPAction(cfg.Name, cfg.URL, cfg.Timeout, func(ctx context.Context, issue detector.Issue) (*http.Request, error) {
		var body []byte
		var err error
		if cfg.Format == FormatSlack {
			body, err = json.Marshal(map[string]string{"text": slackText(issue)})
		} else {
			body, err = json.Marshal(NewRecord(issue))
		}
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range cfg.Headers {
			req.Header.Set(k, v)
		}
		return req, nil
	})
}
