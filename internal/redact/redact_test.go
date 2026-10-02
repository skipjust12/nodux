package redact

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRedactor_Defaults(t *testing.T) {
	r, err := New(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"connecting with password=hunter2 now":          "connecting with password=[REDACTED] now",
		`{"api_key": "abc123", "user": "bob"}`:          `{"api_key": "[REDACTED]", "user": "bob"}`,
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x":  "Authorization: Bearer [REDACTED]",
		"dial postgres://app:s3cr3t@db:5432/app failed": "dial postgres://app:[REDACTED]@db:5432/app failed",
		"key AKIAABCDEFGHIJKLMNOP leaked":               "key [REDACTED] leaked",
		"TOKEN=a TOKEN=b":                               "TOKEN=[REDACTED] TOKEN=[REDACTED]",
		"nothing to see here, token count is high":      "nothing to see here, token count is high",
		"server --token abc123 --port 80":               "server --token [REDACTED] --port 80",
		"mysqld -p --password s3cret":                   "mysqld -p --password [REDACTED]",
		"rotate --api-key=k1 --secret -v":               "rotate --api-key=[REDACTED] --secret -v",
	} {
		if got := r.String(in); got != want {
			t.Errorf("String(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestRedactor_CustomPatternsOnly(t *testing.T) {
	r, err := New([]string{`\b\d{16}\b`, `session=(?P<secret>\w+)`}, false)
	if err != nil {
		t.Fatal(err)
	}
	got := r.String("card 4111111111111111 session=abc password=kept")
	if got != "card [REDACTED] session=[REDACTED] password=kept" {
		t.Errorf("got %q", got)
	}
	if _, err := New([]string{"("}, false); err == nil {
		t.Error("expected an error for an invalid pattern")
	}
}

func TestRedactor_NilIsNoop(t *testing.T) {
	var r *Redactor
	if r.String("password=x") != "password=x" {
		t.Error("nil redactor changed the input")
	}
}

func TestURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T0/B0/SECRET": "https://hooks.slack.com/…",
		"https://user:pw@example.com":                   "https://example.com",
		"https://example.com?token=x":                   "https://example.com/…",
		"not a url":                                     "(invalid URL)",
	} {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErr_StripsURLFromHTTPErrors(t *testing.T) {
	c := &http.Client{Timeout: time.Second}
	_, err := c.Get("http://127.0.0.1:1/services/T0/B0/SECRETTOKEN")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if !strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("precondition: net/http should include the URL: %v", err)
	}
	got := Err(err).Error()
	if strings.Contains(got, "SECRETTOKEN") || !strings.Contains(got, "http://127.0.0.1:1/…") {
		t.Errorf("Err() = %q", got)
	}
	plain := errors.New("plain")
	if Err(plain) != plain {
		t.Error("non-URL errors should pass through")
	}
}
