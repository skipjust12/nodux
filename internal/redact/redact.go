// Package redact scrubs secrets from text before it leaves the host:
// container logs and messages on their way to a webhook or an LLM, and
// URLs (webhook, heartbeat) on their way into nodux's own logs.
package redact

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const Mask = "[REDACTED]"

// DefaultPatterns catch the usual ways secrets end up in logs. If a
// pattern has a group named "secret", only that group is masked, so
// the key name stays readable ("password=[REDACTED]").
var DefaultPatterns = []string{
	// key=value / key: value / "key": "value"
	`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)["']?\s*[:=]\s*["']?(?P<secret>[^\s"',;&]+)`,
	`(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{8,})`,
	// Credentials embedded in a URL: scheme://user:secret@host
	`://[^/\s:@]+:(?P<secret>[^@\s/]+)@`,
	// AWS access key IDs, GitHub/Slack/Anthropic-style tokens.
	`\bAKIA[0-9A-Z]{16}\b`,
	`\bgh[pousr]_[A-Za-z0-9]{30,}\b`,
	`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`,
	`\bsk-[A-Za-z0-9_-]{20,}\b`,
}

type Redactor struct {
	patterns []*regexp.Regexp
}

// New compiles the given patterns, after the defaults if useDefaults.
func New(patterns []string, useDefaults bool) (*Redactor, error) {
	var all []string
	if useDefaults {
		all = append(all, DefaultPatterns...)
	}
	all = append(all, patterns...)

	r := &Redactor{}
	for _, p := range all {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redact pattern %q: %w", p, err)
		}
		r.patterns = append(r.patterns, re)
	}
	return r, nil
}

// String masks every match of every pattern in s. A nil Redactor is a
// no-op.
func (r *Redactor) String(s string) string {
	if r == nil {
		return s
	}
	for _, re := range r.patterns {
		s = maskAll(re, s)
	}
	return s
}

// Strings redacts a slice in place and returns it.
func (r *Redactor) Strings(ss []string) []string {
	for i, s := range ss {
		ss[i] = r.String(s)
	}
	return ss
}

func maskAll(re *regexp.Regexp, s string) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	group := re.SubexpIndex("secret")

	var b strings.Builder
	last := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		if group > 0 && m[2*group] >= 0 {
			start, end = m[2*group], m[2*group+1]
		}
		b.WriteString(s[last:start])
		b.WriteString(Mask)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// URL returns a form of raw that's safe to log: scheme and host only.
// Webhook and heartbeat URLs often are the credential (Slack, Discord,
// healthchecks.io), so the path, query and userinfo never get logged.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	if u.Path == "" && u.RawQuery == "" {
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// Err strips the request URL from an error returned by net/http:
// *url.Error prints the full URL, which leaks it into logs.
func Err(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, URL(ue.URL), ue.Err)
	}
	return err
}
