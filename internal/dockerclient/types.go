package dockerclient

// ContainerSummary is one entry of the GET /containers/json response.
type ContainerSummary struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

// ContainerInspect is the GET /containers/{id}/json response (only the
// fields we actually need).
type ContainerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Tty bool `json:"Tty"`
	} `json:"Config"`
	State struct {
		Status     string  `json:"Status"`
		Running    bool    `json:"Running"`
		Restarting bool    `json:"Restarting"`
		OOMKilled  bool    `json:"OOMKilled"`
		ExitCode   int     `json:"ExitCode"`
		StartedAt  string  `json:"StartedAt"`
		FinishedAt string  `json:"FinishedAt"`
		Health     *Health `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
}

// Health is State.Health; it's nil for containers without a healthcheck.
type Health struct {
	Status        string      `json:"Status"` // starting, healthy, unhealthy
	FailingStreak int         `json:"FailingStreak"`
	Log           []HealthLog `json:"Log"`
}

type HealthLog struct {
	ExitCode int    `json:"ExitCode"`
	Output   string `json:"Output"`
}

// Event is one message of the GET /events stream.
type Event struct {
	Type     string `json:"Type"`
	Action   string `json:"Action"`
	Actor    Actor  `json:"Actor"`
	TimeNano int64  `json:"timeNano"`
}

type Actor struct {
	ID         string            `json:"ID"`
	Attributes map[string]string `json:"Attributes"`
}
