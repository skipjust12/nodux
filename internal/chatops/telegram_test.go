package chatops

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/llm"
)

const token = "123:SECRET"

type fakeTelegram struct {
	mu      sync.Mutex
	updates []map[string]any
	offsets []int64
	sent    chan map[string]any
	actions int
}

func newFakeTelegram(t *testing.T) (*fakeTelegram, string) {
	t.Helper()
	f := &fakeTelegram{sent: make(chan map[string]any, 16)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/bot" + token + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, `{"ok":false,"description":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		reply := func(result any) {
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
		}
		switch strings.TrimPrefix(r.URL.Path, prefix) {
		case "getMe":
			reply(map[string]any{"id": 1, "username": "nodux_bot"})
		case "getUpdates":
			f.mu.Lock()
			off, _ := body["offset"].(float64)
			f.offsets = append(f.offsets, int64(off))
			var out []map[string]any
			for _, u := range f.updates {
				if int64(u["update_id"].(int)) >= int64(off) {
					out = append(out, u)
				}
			}
			f.mu.Unlock()
			if len(out) == 0 {
				select {
				case <-time.After(50 * time.Millisecond):
				case <-r.Context().Done():
				}
			}
			reply(out)
		case "sendMessage":
			f.sent <- body
			reply(map[string]any{"message_id": 99})
		case "sendChatAction":
			f.mu.Lock()
			f.actions++
			f.mu.Unlock()
			reply(true)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func (f *fakeTelegram) push(id int, chat int64, text string, date time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, map[string]any{
		"update_id": id,
		"message": map[string]any{
			"message_id": id * 10, "date": date.Unix(), "text": text,
			"chat": map[string]any{"id": chat, "type": "private"},
			"from": map[string]any{"id": chat, "username": "op"},
		},
	})
}

func (f *fakeTelegram) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-f.sent:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a reply")
		return nil
	}
}

type fakeAnswerer struct {
	mu        sync.Mutex
	questions []string
	open      []detector.Issue
	err       error
}

func (f *fakeAnswerer) Answer(_ context.Context, q string, open []detector.Issue) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.questions = append(f.questions, q)
	f.open = open
	if f.err != nil {
		return "", f.err
	}
	return "api is crash-looping: db is down.", nil
}

type fakeTools struct{}

func (fakeTools) Call(_ context.Context, name string, input json.RawMessage) (string, error) {
	return name + " " + string(input), nil
}

func runBot(t *testing.T, cfg Config) *Bot {
	t.Helper()
	b := New(cfg)
	b.backoff = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return b
}

func TestBot_AnswersAllowedChatsOnly(t *testing.T) {
	tg, url := newFakeTelegram(t)
	ans := &fakeAnswerer{}
	open := []detector.Issue{{Detector: "crashloop", Container: detector.ContainerSnapshot{Name: "api"}, Message: "restarted 3 times", DetectedAt: time.Now().Add(-5 * time.Minute)}}
	runBot(t, Config{
		Token: token, baseURL: url, AllowedChats: []int64{42},
		Answerer: ans, Tools: fakeTools{}, Host: "vps1",
		OpenAlerts: func() []detector.Issue { return open },
	})

	now := time.Now()
	tg.push(1, 666, "что с api?", now)                  // not allowed: ignored
	tg.push(2, 42, "что с api?", now)                   // answered by the LLM
	tg.push(3, 42, "old question", now.Add(-time.Hour)) // stale: ignored
	tg.push(4, 42, "/status", now)
	tg.push(5, 42, "/alerts@nodux_bot api", now)
	tg.push(6, 42, "/status@other_bot", now) // for another bot in the group

	m := tg.next(t)
	if m["chat_id"].(float64) != 42 || m["text"] != "api is crash-looping: db is down." {
		t.Fatalf("reply = %v", m)
	}
	if rp, _ := m["reply_parameters"].(map[string]any); rp["message_id"].(float64) != 20 {
		t.Errorf("not a reply to the question: %v", m)
	}
	m = tg.next(t)
	text := m["text"].(string)
	if !strings.Contains(text, "1 open alerts:") || !strings.Contains(text, "crashloop api (5m0s): restarted 3 times") || !strings.Contains(text, "list_containers") {
		t.Errorf("/status = %q", text)
	}
	m = tg.next(t)
	if text := m["text"].(string); !strings.Contains(text, `alert_history {"hours":24,"name":"api"}`) {
		t.Errorf("/alerts = %q", text)
	}
	select {
	case m := <-tg.sent:
		t.Fatalf("unexpected reply: %v", m)
	case <-time.After(150 * time.Millisecond):
	}

	ans.mu.Lock()
	defer ans.mu.Unlock()
	if len(ans.questions) != 1 || ans.questions[0] != "что с api?" || len(ans.open) != 1 {
		t.Errorf("questions = %q, open = %v", ans.questions, ans.open)
	}
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if tg.actions == 0 {
		t.Error("no typing indicator while thinking")
	}
	if last := tg.offsets[len(tg.offsets)-1]; last != 7 {
		t.Errorf("updates not confirmed: offset %d", last)
	}
}

func TestBot_WithoutLLMAndBudget(t *testing.T) {
	tg, url := newFakeTelegram(t)
	runBot(t, Config{Token: token, baseURL: url, AllowedChats: []int64{42}})
	tg.push(1, 42, "что с api?", time.Now())
	if text := tg.next(t)["text"].(string); !strings.Contains(text, "LLM layer is off") {
		t.Errorf("reply = %q", text)
	}
	tg.push(2, 42, "/help", time.Now())
	if text := tg.next(t)["text"].(string); !strings.Contains(text, "/status") || strings.Contains(text, "just ask") {
		t.Errorf("help = %q", text)
	}

	tg2, url2 := newFakeTelegram(t)
	runBot(t, Config{Token: token, baseURL: url2, AllowedChats: []int64{42}, Answerer: &fakeAnswerer{err: llm.ErrBudgetExhausted}})
	tg2.push(1, 42, "status?", time.Now())
	if text := tg2.next(t)["text"].(string); !strings.Contains(text, "budget") {
		t.Errorf("reply = %q", text)
	}
}

func TestBot_ErrorsDontLeakToken(t *testing.T) {
	b := New(Config{Token: token, baseURL: "http://127.0.0.1:1"})
	err := b.call(context.Background(), "getMe", nil, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}
