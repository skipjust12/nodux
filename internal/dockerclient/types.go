package dockerclient

// ContainerSummary is one entry of the GET /containers/json response.
type ContainerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"` // running, exited, restarting, ...
	Labels map[string]string `json:"Labels"`
}

// ContainerInspect is the GET /containers/{id}/json response (only the
// fields we actually need).
type ContainerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Tty        bool              `json:"Tty"`
		StopSignal string            `json:"StopSignal"` // e.g. "SIGQUIT"; empty = SIGTERM
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Memory    int64 `json:"Memory"`    // memory limit in bytes, 0 = unlimited
		NanoCPUs  int64 `json:"NanoCpus"`  // --cpus, in 1e-9 CPUs
		CPUQuota  int64 `json:"CpuQuota"`  // --cpu-quota, µs per period
		CPUPeriod int64 `json:"CpuPeriod"` // --cpu-period, µs; 0 = 100ms
	} `json:"HostConfig"`
	State struct {
		Status     string  `json:"Status"`
		Running    bool    `json:"Running"`
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

// ProjectLabel is the label compose puts on every container it creates.
const ProjectLabel = "com.docker.compose.project"

// CPULimit is the container's CPU limit in CPUs, 0 if it has none.
func (c *ContainerInspect) CPULimit() float64 {
	h := c.HostConfig
	if h.NanoCPUs > 0 {
		return float64(h.NanoCPUs) / 1e9
	}
	if h.CPUQuota > 0 {
		period := h.CPUPeriod
		if period <= 0 {
			period = 100000
		}
		return float64(h.CPUQuota) / float64(period)
	}
	return 0
}

// Stats is the GET /containers/{id}/stats response (the parts nodux
// uses: memory, and CPU throttling).
type Stats struct {
	CPUStats struct {
		ThrottlingData struct {
			Periods          uint64 `json:"periods"`
			ThrottledPeriods uint64 `json:"throttled_periods"`
			ThrottledTime    uint64 `json:"throttled_time"` // ns
		} `json:"throttling_data"`
	} `json:"cpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// MemoryUsed is the container's working set, computed the same way as
// docker stats: usage minus inactive page cache, which the kernel can
// reclaim before it ever OOM-kills anything. The key is
// total_inactive_file on cgroup v1 and inactive_file on cgroup v2.
func (s *Stats) MemoryUsed() uint64 {
	m := s.MemoryStats
	inactive, ok := m.Stats["total_inactive_file"]
	if !ok {
		inactive = m.Stats["inactive_file"]
	}
	if inactive > m.Usage {
		return 0
	}
	return m.Usage - inactive
}
