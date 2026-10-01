package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	// DefaultTelegramAPI is the Bot API endpoint; overridable for a
	// local Bot API server.
	DefaultTelegramAPI = "https://api.telegram.org"

	telegramMaxMessage = 3800 // the limit is 4096 characters after entity parsing
	telegramLogLines   = 10
	telegramLineMax    = 300
)

type TelegramConfig struct {
	Name     string
	BotToken string
	// ChatID is a numeric chat ID (-100... for channels and supergroups)
	// or @channelusername.
	ChatID string
	// ThreadID posts into a forum topic; 0 = the main chat.
	ThreadID int
	APIURL   string
	Timeout  time.Duration
}

// NewTelegram sends each alert as a Telegram message through a bot.
// Resolutions arrive without a notification sound.
func NewTelegram(cfg TelegramConfig) *HTTPAction {
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultTelegramAPI
	}
	if cfg.Name == "" {
		cfg.Name = "telegram"
	}
	endpoint := strings.TrimRight(cfg.APIURL, "/") + "/bot" + cfg.BotToken + "/sendMessage"
	return newHTTPAction(cfg.Name, cfg.APIURL, cfg.Timeout, func(ctx context.Context, issue detector.Issue) (*http.Request, error) {
		msg := map[string]any{
			"chat_id":              cfg.ChatID,
			"text":                 telegramText(issue),
			"parse_mode":           "HTML",
			"disable_notification": issue.Resolved,
			"link_preview_options": map[string]bool{"is_disabled": true},
		}
		if cfg.ThreadID != 0 {
			msg["message_thread_id"] = cfg.ThreadID
		}
		body, err := json.Marshal(msg)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
}

// telegramText renders an issue as Telegram HTML, under the message
// size limit: log lines are dropped oldest-first until it fits.
func telegramText(issue detector.Issue) string {
	var head strings.Builder
	fmt.Fprintf(&head, "<b>%s</b>", html.EscapeString(headline(issue)))
	if s := subject(issue); s != "" {
		fmt.Fprintf(&head, " <code>%s</code>", html.EscapeString(s))
	}
	if issue.Host != "" {
		fmt.Fprintf(&head, " on %s", html.EscapeString(issue.Host))
	}
	head.WriteString("\n")
	head.WriteString(escapeHTML(issue.Message, 2000))
	if issue.Analysis != "" {
		fmt.Fprintf(&head, "\n<blockquote>%s</blockquote>", escapeHTML(issue.Analysis, 800))
	}
	text := head.String()

	lines := lastLines(issue.Logs, telegramLogLines, telegramLineMax)
	for i := range lines {
		lines[i] = escapeHTML(lines[i], 2*telegramLineMax)
	}
	for len(lines) > 0 {
		block := "\n<pre>" + strings.Join(lines, "\n") + "</pre>"
		if len(text)+len(block) <= telegramMaxMessage {
			return text + block
		}
		lines = lines[1:]
	}
	return text
}

// escapeHTML escapes s for Telegram's HTML mode, cutting it (never
// inside an entity) so the escaped text is at most max bytes plus "…".
func escapeHTML(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		e := html.EscapeString(string(r))
		if b.Len()+len(e) > max {
			b.WriteString("…")
			break
		}
		b.WriteString(e)
	}
	return b.String()
}
