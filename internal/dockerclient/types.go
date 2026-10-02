package dockerclient

// ContainerSummary is one entry of the GET /containers/json response.
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`   // as configured: nginx:1.27
	ImageID string            `json:"ImageID"` // sha256:...
	Created int64             `json:"Created"` // unix seconds
	State   string            `json:"State"`   // running, exited, restarting, ...
	Status  string            `json:"Status"`  // "Up 3 hours (unhealthy)", "Exited (1) 2 minutes ago"
	Labels  map[string]string `json:"Labels"`
}

// ContainerInspect is the GET /containers/{id}/json response (only the
// fields we actually need).
type ContainerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Image   string `json:"Image"` // image ID (sha256:...)
	LogPath string `json:"LogPath"`
	Config  struct {
		Tty        bool              `json:"Tty"`
		StopSignal string            `json:"StopSignal"` // e.g. "SIGQUIT"; empty = SIGTERM
		Image      string            `json:"Image"`      // as given to docker run: "nginx:1.27"
		Labels     map[string]string `json:"Labels"`
		Env        []string          `json:"Env"`
		Cmd        []string          `json:"Cmd"`
		Entrypoint []string          `json:"Entrypoint"`
	} `json:"Config"`
	HostConfig struct {
		Memory        int64 `json:"Memory"`    // memory limit in bytes, 0 = unlimited
		NanoCpus      int64 `json:"NanoCpus"`  // --cpus, in 1e-9 CPUs
		CPUQuota      int64 `json:"CpuQuota"`  // --cpu-quota, µs per period
		CPUPeriod     int64 `json:"CpuPeriod"` // --cpu-period, µs; 0 = 100ms
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	State struct {
		Status     string  `json:"Status"`
		Running    bool    `json:"Running"`
		OOMKilled  bool    `json:"OOMKilled"`
		ExitCode   int     `json:"ExitCode"`
		Error      string  `json:"Error"`
		StartedAt  string  `json:"StartedAt"`
		FinishedAt string  `json:"FinishedAt"`
		Health     *Health `json:"Health"`
	} `json:"State"`
	RestartCount int     `json:"RestartCount"`
	Mounts       []Mount `json:"Mounts"`
}

type Mount struct {
	Type        string `json:"Type"` // bind, volume, tmpfs
	Name        string `json:"Name"` // volume name
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
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

// CPULimit is the container's CPU limit in CPUs, 0 if it has none.
func (c *ContainerInspect) CPULimit() float64 {
	h := c.HostConfig
	if h.NanoCpus > 0 {
		return float64(h.NanoCpus) / 1e9
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

// Stats is the GET /containers/{id}/stats response.
type Stats struct {
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	CPUStats    CPUStats `json:"cpu_stats"`
	PreCPUStats CPUStats `json:"precpu_stats"`
	PidsStats   struct {
		Current uint64 `json:"current"`
	} `json:"pids_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats struct {
		IOServiceBytesRecursive []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

type CPUStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemUsage    uint64 `json:"system_cpu_usage"`
	OnlineCPUs     uint32 `json:"online_cpus"`
	ThrottlingData struct {
		Periods          uint64 `json:"periods"`
		ThrottledPeriods uint64 `json:"throttled_periods"`
		ThrottledTime    uint64 `json:"throttled_time"`
	} `json:"throttling_data"`
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

// CPUPercent is CPU usage between the two samples of a non-one-shot
// stats call, the way docker stats computes it (100% = one full core).
// ok is false when there's no previous sample to compare with.
func (s *Stats) CPUPercent() (pct float64, ok bool) {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if s.PreCPUStats.SystemUsage == 0 || sysDelta <= 0 || cpuDelta < 0 {
		return 0, false
	}
	cpus := float64(s.CPUStats.OnlineCPUs)
	if cpus == 0 {
		cpus = 1
	}
	return cpuDelta / sysDelta * cpus * 100, true
}

// Top is the GET /containers/{id}/top response: ps output, one row per
// process, columns named by Titles.
type Top struct {
	Titles    []string   `json:"Titles"`
	Processes [][]string `json:"Processes"`
}

// DiskUsage is the GET /system/df response (the parts we report).
type DiskUsage struct {
	LayersSize int64 `json:"LayersSize"`
	Images     []struct {
		ID         string   `json:"Id"`
		RepoTags   []string `json:"RepoTags"`
		Size       int64    `json:"Size"`
		SharedSize int64    `json:"SharedSize"`
		Containers int64    `json:"Containers"` // -1 when not computed
	} `json:"Images"`
	Containers []struct {
		ID     string   `json:"Id"`
		Names  []string `json:"Names"`
		SizeRw int64    `json:"SizeRw"`
		State  string   `json:"State"`
	} `json:"Containers"`
	Volumes []struct {
		Name      string `json:"Name"`
		UsageData *struct {
			Size     int64 `json:"Size"`
			RefCount int64 `json:"RefCount"`
		} `json:"UsageData"`
	} `json:"Volumes"`
	BuildCache []struct {
		Size   int64 `json:"Size"`
		InUse  bool  `json:"InUse"`
		Shared bool  `json:"Shared"`
	} `json:"BuildCache"`
}
