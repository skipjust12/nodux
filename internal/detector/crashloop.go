package detector

import (
	"fmt"
	"time"
)

// CrashLoopDetector срабатывает, если контейнер перезапустился больше
// threshold раз за скользящее окно window.
//
// Docker не хранит историю рестартов, только суммарный RestartCount с
// момента создания контейнера — поэтому детектор сам восстанавливает
// историю: на каждом опросе смотрит на прирост RestartCount и запоминает
// момент опроса как время рестарта (точность до интервала опроса).
type CrashLoopDetector struct {
	threshold int
	window    time.Duration
	state     map[string]*crashLoopState
	now       func() time.Time // для тестируемости
}

type crashLoopState struct {
	lastRestartCount int
	events           []time.Time
	lastAlertedCount int
}

func NewCrashLoopDetector(threshold int, window time.Duration) *CrashLoopDetector {
	return &CrashLoopDetector{
		threshold: threshold,
		window:    window,
		state:     make(map[string]*crashLoopState),
		now:       time.Now,
	}
}

func (d *CrashLoopDetector) Name() string { return "crashloop" }

func (d *CrashLoopDetector) Check(s ContainerSnapshot) *Issue {
	now := d.now()

	st, ok := d.state[s.ID]
	if !ok {
		// Первый раз видим контейнер — просто запоминаем точку отсчёта,
		// прошлые рестарты до старта демона нам не известны.
		d.state[s.ID] = &crashLoopState{
			lastRestartCount: s.RestartCount,
			lastAlertedCount: -1,
		}
		return nil
	}

	if s.RestartCount > st.lastRestartCount {
		delta := s.RestartCount - st.lastRestartCount
		for i := 0; i < delta; i++ {
			st.events = append(st.events, now)
		}
		st.lastRestartCount = s.RestartCount
	}

	cutoff := now.Add(-d.window)
	kept := st.events[:0]
	for _, t := range st.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.events = kept

	if len(st.events) < d.threshold {
		return nil
	}
	if st.lastAlertedCount == s.RestartCount {
		// Уже сигнализировали об этой серии рестартов, ждём следующего рестарта.
		return nil
	}
	st.lastAlertedCount = s.RestartCount

	return &Issue{
		Detector:   d.Name(),
		Severity:   "critical",
		Message:    fmt.Sprintf("container restarted %d times in the last %s", len(st.events), d.window),
		Container:  s,
		DetectedAt: now,
	}
}
