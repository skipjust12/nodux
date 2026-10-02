package action

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
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
	telegramItemMax    = 400
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

// NewTelegram sends each notification as a Telegram message through a
// bot. Resolutions and digests arrive without a notification sound.
func NewTelegram(cfg TelegramConfig) *HTTPAction {
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultTelegramAPI
	}
	if cfg.Name == "" {
		cfg.Name = "telegram"
	}
	endpoint := strings.TrimRight(cfg.APIURL, "/") + "/bot" + cfg.BotToken + "/sendMessage"
	return newHTTPAction(cfg.Name, endpoint, nil, cfg.Timeout, func(n Notification) ([][]byte, error) {
		msg := map[string]any{
			"chat_id":              cfg.ChatID,
			"text":                 telegramText(n),
			"parse_mode":           "HTML",
			"disable_notification": !firing(n.Alerts),
			"link_preview_options": map[string]bool{"is_disabled": true},
		}
		if cfg.ThreadID != 0 {
			msg["message_thread_id"] = cfg.ThreadID
		}
		b, err := json.Marshal(msg)
		return [][]byte{b}, err
	})
}

// telegramText renders a notification as Telegram HTML, under the
// message size limit: log lines are dropped oldest-first until it fits.
func telegramText(n Notification) string {
	if n.Digest != nil {
		return mrkdwnToHTML(n.Digest.Text, telegramMaxMessage)
	}
	if len(n.Alerts) == 1 {
		suffix := ""
		if n.IncidentID != 0 && n.Update {
			suffix = fmt.Sprintf(" (incident #%d)", n.IncidentID)
		}
		return telegramAlert(n.Alerts[0], suffix)
	}

	var b strings.Builder
	label, nFiring, nResolved := batchLabel(n.Alerts)
	fmt.Fprintf(&b, "<b>[%s] incident #%d</b>", label, n.IncidentID)
	if n.Update {
		b.WriteString(" (update)")
	}
	if host := n.Alerts[0].Host; host != "" {
		fmt.Fprintf(&b, " on %s", html.EscapeString(host))
	}
	switch {
	case nFiring > 0 && nResolved > 0:
		fmt.Fprintf(&b, ": %d new, %d resolved", nFiring, nResolved)
	case nFiring > 0:
		fmt.Fprintf(&b, ": %d alerts", nFiring)
	default:
		fmt.Fprintf(&b, ": %d resolved", nResolved)
	}
	if n.Summary != "" {
		fmt.Fprintf(&b, "\n<blockquote>%s</blockquote>", escapeHTML(n.Summary, 800))
	}
	for _, issue := range n.Alerts {
		item := "<b>" + html.EscapeString(issue.Detector) + "</b>"
		if issue.Resolved {
			item = "resolved " + item
		}
		if s := subject(issue); s != "" {
			item += " <code>" + html.EscapeString(s) + "</code>"
		}
		fmt.Fprintf(&b, "\n• %s: %s", item, escapeHTML(issue.Message, telegramItemMax))
	}
	return withPre(cutHTML(b.String()), firstLogs(n.Alerts))
}

func telegramAlert(issue detector.Issue, suffix string) string {
	var head strings.Builder
	fmt.Fprintf(&head, "<b>%s</b>", html.EscapeString(headline(issue)))
	if s := subject(issue); s != "" {
		fmt.Fprintf(&head, " <code>%s</code>", html.EscapeString(s))
	}
	if issue.Host != "" {
		fmt.Fprintf(&head, " on %s", html.EscapeString(issue.Host))
	}
	head.WriteString(suffix)
	head.WriteString("\n")
	head.WriteString(escapeHTML(issue.Message, 2000))
	if issue.Analysis != "" {
		fmt.Fprintf(&head, "\n<blockquote>%s</blockquote>", escapeHTML(issue.Analysis, 800))
	}
	return withPre(head.String(), issue.Logs)
}

// withPre appends the newest log lines in a <pre> block, dropping the
// oldest until the message fits.
func withPre(text string, logs []string) string {
	lines := lastLines(logs, telegramLogLines, telegramLineMax)
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

// cutHTML cuts a message built from whole lines of balanced HTML at a
// line boundary, so no tag is left open.
func cutHTML(s string) string {
	if len(s) <= telegramMaxMessage {
		return s
	}
	cut := strings.LastIndex(s[:telegramMaxMessage-len("\n…")], "\n")
	if cut < 0 {
		return escapeHTML(html.UnescapeString(s), telegramMaxMessage)
	}
	return s[:cut] + "\n…"
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

var (
	mrkdwnBold = regexp.MustCompile(`\*([^*\n]+)\*`)
	mrkdwnCode = regexp.MustCompile("`([^`\n]+)`")
)

// mrkdwnToHTML turns the digest's Slack mrkdwn (*bold*, `code`) into
// Telegram HTML, cut at a line boundary to fit.
func mrkdwnToHTML(s string, max int) string {
	var out []string
	size := 0
	for _, line := range strings.Split(s, "\n") {
		l := html.EscapeString(line)
		l = mrkdwnCode.ReplaceAllString(l, "<code>$1</code>")
		l = mrkdwnBold.ReplaceAllString(l, "<b>$1</b>")
		if size+len(l)+1 > max-len("…") {
			out = append(out, "…")
			break
		}
		out = append(out, l)
		size += len(l) + 1
	}
	return strings.Join(out, "\n")
}

// firing reports whether any alert is firing (not a resolution).
func firing(alerts []detector.Issue) bool {
	for _, a := range alerts {
		if !a.Resolved {
			return true
		}
	}
	return false
}
