// Package detector определяет общий контракт для всех детекторов проблем
// с контейнерами. Каждый детектор получает снимок состояния контейнера на
// момент опроса и решает, есть ли проблема; логи и раздача действий —
// забота движка (engine), а не самого детектора.
package detector

import "time"

// ContainerSnapshot — состояние контейнера на момент опроса, собранное
// из docker inspect.
type ContainerSnapshot struct {
	ID           string
	Name         string
	Status       string // running, exited, restarting, ...
	RestartCount int
	ExitCode     int
	OOMKilled    bool
	StartedAt    time.Time
	FinishedAt   time.Time
}

// Issue — обнаруженная проблема. Logs заполняется движком после того, как
// детектор её вернул (чтобы не тянуть логи контейнеров, с которыми всё в порядке).
type Issue struct {
	Detector   string
	Severity   string
	Message    string
	Container  ContainerSnapshot
	DetectedAt time.Time
	Logs       []string
}

// Detector — интерфейс, который должен реализовать любой детектор проблем.
// Check вызывается на каждом опросе для каждого немониторимого-исключённого
// контейнера; детектор сам решает, нужно ли хранить состояние между вызовами.
type Detector interface {
	Name() string
	Check(snapshot ContainerSnapshot) *Issue
}
