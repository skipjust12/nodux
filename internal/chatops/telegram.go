// Package chatops is a Telegram bot for asking nodux about the host:
// "what's up with api?" gets an answer from the LLM layer, which looks
// with the same read-only tools it uses on alerts. /status and /alerts
// work without the LLM.
//
// The bot long-polls Telegram, so nothing on the host listens for
// connections. It only talks to chats on its allowlist; everything
// else is ignored (and the chat ID logged once, to make setup easy).
package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/llm"
	"github.com/skipjust12/nodux/internal/redact"
)

const (
	defaultAPI   = "https://api.telegram.org"
	pollTimeout  = 50 * time.Second
	maxMessage   = 4000 // Telegram's limit is 4096 UTF-16 units; bytes are never fewer
	maxQuestion  = 1000
	staleMessage = 10 * time.Minute
	maxBackoff   = time.Minute
)

// Answerer is the LLM layer.
type Answerer interface {
	Answer(ctx context.Context, question string, open []detector.Issue) (string, error)
}

// Tools runs the read-only tools for the commands that don't need the LLM.
type Tools interface {
	Call(ctx context.Context, name string, input json.RawMessage) (string, error)
}

type Config struct {
	Token        string
	AllowedChats []int64
	Answerer     Answerer // nil: commands only
	Tools        Tools
	OpenAlerts   func() []detector.Issue
	Host         string
	baseURL      string // tests
}

type Bot struct {
	cfg     Config
	allowed map[int64]bool
	client  *http.Client
	api     string
	now     func() time.Time
	backoff time.Duration

	mu     sync.Mutex
	warned map[int64]bool
}

func New(cfg Config) *Bot {
	allowed := make(map[int64]bool, len(cfg.AllowedChats))
	for _, id := range cfg.AllowedChats {
		allowed[id] = true
	}
	base := cfg.baseURL
	if base == "" {
		base = defaultAPI
	}
	return &Bot{
		cfg:     cfg,
		allowed: allowed,
		client:  &http.Client{Timeout: pollTimeout + 15*time.Second},
		api:     strings.TrimSuffix(base, "/") + "/bot" + cfg.Token,
		now:     time.Now,
		backoff: time.Second,
		warned:  make(map[int64]bool),
	}
}

type update struct {
	UpdateID int64    `json:"update_id"`
	Message  *message `json:"message"`
}

type message struct {
	MessageID int64  `json:"message_id"`
	Date      int64  `json:"date"`
	Text      string `json:"text"`
	Chat      struct {
		ID    int64  `json:"id"`
		Type  string `json:"type"`
		Title string `json:"title"`
	} `json:"chat"`
	From struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"from"`
}

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Run polls for messages until ctx is cancelled.
func (b *Bot) Run(ctx context.Context) {
	var me struct {
		Username string `json:"username"`
	}
	backoff := b.backoff
	for {
		err := b.call(ctx, "getMe", nil, &me)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		slog.Error("telegram bot can't start, will retry", "error", err, "retry_in", backoff.String())
		if !sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
	if len(b.allowed) == 0 {
		slog.Warn("telegram bot answers no one: chatops.telegram.allowed_chat_ids is empty; write to the bot and look for the chat ID in this log")
	}
	slog.Info("telegram bot ready", "bot", "@"+me.Username, "allowed_chats", len(b.allowed))

	var offset int64
	backoff = b.backoff
	for {
		var updates []update
		err := b.call(ctx, "getUpdates", map[string]any{
			"offset":          offset,
			"timeout":         int(pollTimeout.Seconds()),
			"allowed_updates": []string{"message"},
		}, &updates)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("telegram getUpdates failed, will retry", "error", err, "retry_in", backoff.String())
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = b.backoff
		for _, u := range updates {
			offset = max(offset, u.UpdateID+1)
			if u.Message != nil {
				b.handle(ctx, me.Username, u.Message)
			}
		}
	}
}

func (b *Bot) handle(ctx context.Context, botName string, m *message) {
	if !b.allowed[m.Chat.ID] {
		b.mu.Lock()
		first := !b.warned[m.Chat.ID]
		b.warned[m.Chat.ID] = true
		b.mu.Unlock()
		if first {
			slog.Info("telegram: ignoring a chat that isn't allowed; add its ID to chatops.telegram.allowed_chat_ids to let it ask", "chat_id", m.Chat.ID, "chat", m.Chat.Title, "user", m.From.Username)
		}
		return
	}
	text := strings.TrimSpace(m.Text)
	if text == "" {
		return
	}
	// Messages left over from while nodux was down: the moment has passed.
	if b.now().Sub(time.Unix(m.Date, 0)) > staleMessage {
		return
	}

	reply := b.respond(ctx, botName, m.Chat.ID, text)
	if reply == "" {
		return
	}
	if err := b.send(ctx, m.Chat.ID, m.MessageID, reply); err != nil {
		slog.Warn("telegram sendMessage failed", "chat_id", m.Chat.ID, "error", err)
	}
}

func (b *Bot) respond(ctx context.Context, botName string, chat int64, text string) string {
	if strings.HasPrefix(text, "/") {
		cmd, arg, _ := strings.Cut(text, " ")
		// In groups, commands come as /status@nodux_bot.
		cmd, target, addressed := strings.Cut(cmd, "@")
		if addressed && !strings.EqualFold(target, botName) {
			return ""
		}
		switch strings.ToLower(cmd) {
		case "/start", "/help":
			return b.help()
		case "/status":
			return b.status(ctx)
		case "/alerts":
			return b.alerts(ctx, strings.TrimSpace(arg))
		}
		return "Unknown command. " + b.help()
	}

	if b.cfg.Answerer == nil {
		return "The LLM layer is off (llm.enabled in nodux's config), so I can only do /status and /alerts."
	}
	b.typing(ctx, chat)
	var open []detector.Issue
	if b.cfg.OpenAlerts != nil {
		open = b.cfg.OpenAlerts()
	}
	answer, err := b.cfg.Answerer.Answer(ctx, detector.Truncate(text, maxQuestion), open)
	switch {
	case errors.Is(err, llm.ErrBudgetExhausted):
		return "The hourly LLM budget (llm.max_per_hour) is used up; try again later, or use /status."
	case err != nil:
		slog.Warn("telegram: answering failed", "error", err)
		return "Sorry, I couldn't get an answer: " + detector.Truncate(err.Error(), 300)
	}
	return answer
}

func (b *Bot) help() string {
	host := ""
	if b.cfg.Host != "" {
		host = " on " + b.cfg.Host
	}
	s := "nodux" + host + ":\n/status: open alerts and containers\n/alerts [container]: alerts of the last 24h"
	if b.cfg.Answerer != nil {
		s += "\nOr just ask, e.g. \"what's wrong with api?\" or \"why is the disk full?\""
	}
	return s
}

func (b *Bot) status(ctx context.Context) string {
	var w strings.Builder
	if b.cfg.OpenAlerts != nil {
		open := b.cfg.OpenAlerts()
		if len(open) == 0 {
			w.WriteString("No open alerts.\n")
		} else {
			fmt.Fprintf(&w, "%d open alerts:\n", len(open))
			for _, issue := range open {
				subject := issue.Container.Name
				if subject == "" {
					subject = issue.Resource
				}
				fmt.Fprintf(&w, "• %s %s (%s): %s\n", issue.Detector, subject, b.now().Sub(issue.DetectedAt).Round(time.Minute), issue.Message)
			}
		}
	}
	if b.cfg.Tools != nil {
		if out, err := b.cfg.Tools.Call(ctx, "list_containers", nil); err != nil {
			fmt.Fprintf(&w, "\nCan't list containers: %v", err)
		} else {
			w.WriteString("\n" + out)
		}
	}
	return w.String()
}

func (b *Bot) alerts(ctx context.Context, name string) string {
	if b.cfg.Tools == nil {
		return "No alert history here."
	}
	input, _ := json.Marshal(map[string]any{"name": name, "hours": 24})
	out, err := b.cfg.Tools.Call(ctx, "alert_history", input)
	if err != nil {
		return "Can't read the alert history: " + err.Error()
	}
	return out
}

func (b *Bot) typing(ctx context.Context, chat int64) {
	b.call(ctx, "sendChatAction", map[string]any{"chat_id": chat, "action": "typing"}, nil)
}

func (b *Bot) send(ctx context.Context, chat, replyTo int64, text string) error {
	return b.call(ctx, "sendMessage", map[string]any{
		"chat_id":              chat,
		"text":                 detector.Truncate(text, maxMessage),
		"reply_parameters":     map[string]any{"message_id": replyTo, "allow_sending_without_reply": true},
		"link_preview_options": map[string]any{"is_disabled": true},
	}, nil)
}

// call invokes a Bot API method. The token is part of the URL, so
// errors never include it.
func (b *Bot) call(ctx context.Context, method string, params any, result any) error {
	body := []byte("{}")
	if params != nil {
		var err error
		if body, err = json.Marshal(params); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.api+"/"+method, bytes.NewReader(body))
	if err != nil {
		return redact.Err(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return redact.Err(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("%s: status %d", method, resp.StatusCode)
	}
	if !out.OK {
		if out.Parameters.RetryAfter > 0 {
			sleep(ctx, time.Duration(out.Parameters.RetryAfter)*time.Second)
		}
		return fmt.Errorf("%s: %s", method, out.Description)
	}
	if result != nil {
		return json.Unmarshal(out.Result, result)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
