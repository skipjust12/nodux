package llm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/skipjust12/nodux/internal/detector"
)

const (
	DefaultModel    = "claude-opus-5-5"
	DefaultEffort   = "low"
	DefaultMaxSteps = 4

	// Room for adaptive thinking, tool calls and a short answer.
	maxTokens     = 8192
	maxAnalysis   = 800
	maxAnswer     = 3500 // Telegram caps a message at 4096
	maxToolResult = 8000 // bytes of one tool's output the model gets to see
)

// Models that accept server-side refusal fallbacks in the "default"
// form; for anything else the field is left out.
var fallbackModels = map[string]bool{
	"claude-opus-5-5":   true,
	"claude-opus-5":     true,
	"claude-fable-5-1":  true,
	"claude-sonnet-5-5": true,
}

type AnthropicConfig struct {
	APIKey  string
	Model   string
	BaseURL string // optional, for a proxy or tests
	// Effort is low, medium, high, xhigh or max.
	Effort string
	// Timeout bounds one whole analysis or answer, tool calls included.
	Timeout time.Duration
	// MaxPerHour caps analyses, answers and digest notes together; 0
	// means no cap.
	MaxPerHour int
	// Toolbox, if set, lets the model investigate with read-only tools
	// for up to MaxSteps rounds of tool calls. MaxSteps 0 means no tools:
	// one request per analysis.
	Toolbox  Toolbox
	MaxSteps int
	// Host is named in the prompts.
	Host string
	// OnUsage, if set, is called with the token usage of every request.
	OnUsage func(Usage)
}

// Anthropic talks to Claude through the Messages API.
type Anthropic struct {
	client   anthropic.Client
	model    string
	effort   anthropic.BetaOutputConfigEffort
	timeout  time.Duration
	toolbox  Toolbox
	tools    []anthropic.BetaToolUnionParam
	maxSteps int
	host     string
	onUsage  func(Usage)

	mu         sync.Mutex
	maxPerHour int
	calls      []time.Time
	now        func() time.Time

	ok, failed, overBudget atomic.Uint64
}

// Budget describes the hourly budget and how requests went so far.
type Budget struct {
	// MaxPerHour is the hourly cap, 0 = none; Remaining is what's left
	// of it right now.
	MaxPerHour int `json:"max_per_hour"`
	Remaining  int `json:"remaining"`
	// Analyses, answers and digest notes since startup.
	OK         uint64 `json:"ok"`
	Failed     uint64 `json:"failed"`
	OverBudget uint64 `json:"over_budget"`
}

func (a *Anthropic) Budget() Budget {
	a.mu.Lock()
	a.pruneLocked()
	used := len(a.calls)
	a.mu.Unlock()
	b := Budget{
		MaxPerHour: a.maxPerHour,
		OK:         a.ok.Load(),
		Failed:     a.failed.Load(),
		OverBudget: a.overBudget.Load(),
	}
	if a.maxPerHour > 0 {
		b.Remaining = max(a.maxPerHour-used, 0)
	}
	return b
}

func NewAnthropic(cfg AnthropicConfig) *Anthropic {
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Effort == "" {
		cfg.Effort = DefaultEffort
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	opts := []option.RequestOption{option.WithAPIKey(cfg.APIKey), option.WithMaxRetries(2)}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	a := &Anthropic{
		client:     anthropic.NewClient(opts...),
		model:      cfg.Model,
		effort:     anthropic.BetaOutputConfigEffort(cfg.Effort),
		timeout:    cfg.Timeout,
		host:       cfg.Host,
		onUsage:    cfg.OnUsage,
		maxPerHour: cfg.MaxPerHour,
		now:        time.Now,
	}
	if cfg.Toolbox != nil && cfg.MaxSteps > 0 {
		a.toolbox, a.maxSteps = cfg.Toolbox, cfg.MaxSteps
		a.tools = toolParams(cfg.Toolbox.Tools())
	}
	return a
}

func toolParams(specs []ToolSpec) []anthropic.BetaToolUnionParam {
	out := make([]anthropic.BetaToolUnionParam, 0, len(specs))
	for _, s := range specs {
		props := s.Properties
		if props == nil {
			props = map[string]any{}
		}
		out = append(out, anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
			Name:        s.Name,
			Description: anthropic.String(s.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{
				Properties:  props,
				Required:    s.Required,
				ExtraFields: map[string]any{"additionalProperties": false},
			},
		}})
	}
	return out
}

// Analyze returns a short note on the incident's probable cause.
func (a *Anthropic) Analyze(ctx context.Context, inc Incident) (string, error) {
	return a.run(ctx, request{
		purpose:  "incident",
		system:   incidentSystem(a.toolbox != nil),
		prompt:   incidentPrompt(inc),
		tools:    true,
		maxChars: maxAnalysis,
	})
}

// Answer answers an operator's question, given the alerts open right now.
func (a *Anthropic) Answer(ctx context.Context, question string, open []detector.Issue) (string, error) {
	return a.run(ctx, request{
		purpose:  "question",
		system:   questionSystem(a.toolbox != nil),
		prompt:   questionPrompt(a.host, question, open, a.now()),
		tools:    true,
		maxChars: maxAnswer,
	})
}

// SummarizeDigest writes the digest's takeaway.
func (a *Anthropic) SummarizeDigest(ctx context.Context, digest string) (string, error) {
	return a.run(ctx, request{
		purpose:  "digest",
		system:   digestSystem(),
		prompt:   "<digest>\n" + digest + "\n</digest>",
		maxChars: maxAnalysis,
	})
}

type request struct {
	purpose  string
	system   string
	prompt   string
	tools    bool
	maxChars int
}

// run applies the hourly budget and counts how the request went.
func (a *Anthropic) run(ctx context.Context, r request) (string, error) {
	if !a.allow() {
		a.overBudget.Add(1)
		return "", ErrBudgetExhausted
	}
	text, err := a.converse(ctx, r)
	if err != nil {
		a.failed.Add(1)
	} else {
		a.ok.Add(1)
	}
	return text, err
}

// converse sends one request, and keeps going while the model asks for
// tools, up to maxSteps rounds of them. The conversation only ever
// grows by appending, so the prompt cache and thinking blocks stay
// valid from one step to the next.
func (a *Anthropic) converse(ctx context.Context, r request) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: maxTokens,
		// The breakpoint on the system prompt caches tools + system
		// across requests; the top-level one moves along with the
		// conversation, so each step re-reads the previous ones.
		System:       []anthropic.BetaTextBlockParam{{Text: r.system, CacheControl: anthropic.NewBetaCacheControlEphemeralParam()}},
		CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(r.prompt)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: a.effort},
	}
	useTools := r.tools && a.toolbox != nil
	if useTools {
		params.Tools = a.tools
	}
	if fallbackModels[a.model] {
		// Logs can trip a safety classifier (think exploit payloads in
		// an access log); let the API re-serve such a request on a
		// fallback model instead of returning nothing.
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
	}

	runID := newRunID()
	for round := 0; ; round++ {
		msg, err := a.client.Beta.Messages.New(ctx, params)
		if err != nil {
			return "", fmt.Errorf("anthropic API: %w", err)
		}
		a.record(runID, r.purpose, msg)

		switch msg.StopReason {
		case anthropic.BetaStopReasonRefusal:
			return "", errors.New("anthropic API: model declined to answer")
		case anthropic.BetaStopReasonToolUse:
			if useTools && round < a.maxSteps {
				break
			}
			fallthrough // tools exhausted (shouldn't happen with tool_choice none): use what's there
		default:
			text := detector.Truncate(strings.TrimSpace(textOf(msg)), r.maxChars)
			if text == "" {
				return "", fmt.Errorf("anthropic API: empty answer (stop reason %q)", msg.StopReason)
			}
			return text, nil
		}

		params.Messages = append(params.Messages, msg.ToParam())
		results := a.callTools(ctx, msg)
		if round+1 >= a.maxSteps {
			// Out of tool rounds: say so and turn tools off. Changing
			// tool_choice keeps the cached prefix and thinking blocks valid,
			// unlike removing the tools.
			results = append(results, anthropic.NewBetaTextBlock("That was your last round of tool calls: answer now with what you have."))
			params.ToolChoice = anthropic.BetaToolChoiceUnionParam{OfNone: &anthropic.BetaToolChoiceNoneParam{}}
		}
		params.Messages = append(params.Messages, anthropic.NewBetaUserMessage(results...))
	}
}

// callTools runs every tool call in a response. All results go back in
// one user message, errors included (as is_error results).
func (a *Anthropic) callTools(ctx context.Context, msg *anthropic.BetaMessage) []anthropic.BetaContentBlockParamUnion {
	var results []anthropic.BetaContentBlockParamUnion
	for _, block := range msg.Content {
		tu, ok := block.AsAny().(anthropic.BetaToolUseBlock)
		if !ok {
			continue
		}
		out, err := a.toolbox.Call(ctx, tu.Name, []byte(tu.JSON.Input.Raw()))
		if err != nil {
			slog.Debug("llm tool call failed", "tool", tu.Name, "error", err)
			results = append(results, anthropic.NewBetaToolResultBlock(tu.ID, detector.Truncate(err.Error(), 1000), true))
			continue
		}
		slog.Debug("llm tool call", "tool", tu.Name, "bytes", len(out))
		results = append(results, anthropic.NewBetaToolResultBlock(tu.ID, detector.Truncate(out, maxToolResult), false))
	}
	return results
}

func textOf(msg *anthropic.BetaMessage) string {
	var parts []string
	for _, block := range msg.Content {
		if text, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			parts = append(parts, text.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func (a *Anthropic) record(run, purpose string, msg *anthropic.BetaMessage) {
	if a.onUsage == nil {
		return
	}
	model := string(msg.Model)
	if model == "" {
		model = a.model
	}
	u := msg.Usage
	a.onUsage(Usage{
		Run:        run,
		Purpose:    purpose,
		Model:      model,
		Input:      u.InputTokens,
		Output:     u.OutputTokens,
		CacheRead:  u.CacheReadInputTokens,
		CacheWrite: u.CacheCreationInputTokens,
	})
}

func newRunID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// allow applies the hourly budget.
func (a *Anthropic) allow() bool {
	if a.maxPerHour <= 0 {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked()
	if len(a.calls) >= a.maxPerHour {
		return false
	}
	a.calls = append(a.calls, a.now())
	return true
}

func (a *Anthropic) pruneLocked() {
	cutoff := a.now().Add(-time.Hour)
	kept := a.calls[:0]
	for _, t := range a.calls {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.calls = kept
}
