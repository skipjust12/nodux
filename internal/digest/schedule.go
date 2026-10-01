package digest

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/skipjust12/nodux/internal/action"
)

// Schedule is when the digest goes out: every day, or every week on
// Weekday, at Hour:Minute local time.
type Schedule struct {
	Weekly  bool
	Weekday time.Weekday
	Hour    int
	Minute  int
}

// ParseSchedule reads the config's every ("daily", "weekly"), at
// ("09:00") and weekday ("monday").
func ParseSchedule(every, at, weekday string) (Schedule, error) {
	var s Schedule
	switch strings.ToLower(every) {
	case "daily":
	case "weekly":
		s.Weekly = true
	default:
		return s, fmt.Errorf("every must be daily or weekly, got %q", every)
	}
	h, m, ok := strings.Cut(at, ":")
	hour, err1 := strconv.Atoi(h)
	minute, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return s, fmt.Errorf("at must be a time like 09:00, got %q", at)
	}
	s.Hour, s.Minute = hour, minute
	if s.Weekly {
		day, ok := weekdays[strings.ToLower(weekday)]
		if !ok {
			return s, fmt.Errorf("weekday must be a day of the week like monday, got %q", weekday)
		}
		s.Weekday = day
	}
	return s, nil
}

var weekdays = map[string]time.Weekday{
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday,
	"thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday,
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// Next is the first scheduled time after now, in now's location.
// Building it from the calendar date keeps it at the same wall-clock
// time across DST changes.
func (s Schedule) Next(now time.Time) time.Time {
	y, m, d := now.Date()
	next := time.Date(y, m, d, s.Hour, s.Minute, 0, 0, now.Location())
	for !next.After(now) || (s.Weekly && next.Weekday() != s.Weekday) {
		d++
		next = time.Date(y, m, d, s.Hour, s.Minute, 0, 0, now.Location())
	}
	return next
}

// Period is the span a digest sent at t covers.
func (s Schedule) Period(t time.Time) (from, to time.Time) {
	if s.Weekly {
		return t.AddDate(0, 0, -7), t
	}
	return t.AddDate(0, 0, -1), t
}

func (s Schedule) Title() string {
	if s.Weekly {
		return "Weekly digest"
	}
	return "Daily digest"
}

// Run sends a digest through the actions on schedule until ctx is
// cancelled. A digest missed while nodux was down is skipped.
func Run(ctx context.Context, s Schedule, b *Builder, actions []action.Action) {
	loc := b.Location
	if loc == nil {
		loc = time.Local
	}
	for {
		next := s.Next(time.Now().In(loc))
		slog.Debug("next digest", "at", next.Format(time.RFC3339))
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		from, to := s.Period(next)
		d, err := b.Build(ctx, s.Title(), from, to)
		if err != nil {
			slog.Error("building digest failed", "error", err)
			continue
		}
		for _, a := range actions {
			if err := a.Send(ctx, action.Notification{Digest: d}); err != nil {
				slog.Error("sending digest failed", "action", a.Name(), "error", err)
			}
		}
	}
}
