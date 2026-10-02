package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/dockertest"
	"github.com/skipjust12/nodux/internal/history"
	"github.com/skipjust12/nodux/internal/redact"
)

func ctr(id, name, status string, labels map[string]string) *dockerclient.ContainerInspect {
	c := &dockerclient.ContainerInspect{ID: id, Name: "/" + name, Image: "sha256:feedface0123456789", Created: "2026-10-01T11:48:00Z"}
	c.State.Status = status
	c.State.Running = status == "running"
	c.Config.Image = name + ":latest"
	c.Config.Labels = labels
	return c
}

func setup(t *testing.T) (*Toolbox, *dockertest.Server) {
	t.Helper()
	srv := dockertest.New(t)
	api := ctr("aaaa1111", "shop-api-1", "running", map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.service": "api"})
	api.Config.Env = []string{"DATABASE_URL=postgres://app:hunter2@db/app", "PORT=8080"}
	api.Config.Cmd = []string{"server", "--password=s3cret"}
	api.HostConfig.Memory = 512 << 20
	api.HostConfig.RestartPolicy.Name = "always"
	api.Mounts = []dockerclient.Mount{{Type: "volume", Name: "uploads", Destination: "/data", RW: true}}
	api.State.Health = &dockerclient.Health{Status: "unhealthy", FailingStreak: 2, Log: []dockerclient.HealthLog{{ExitCode: 1, Output: "503"}}}
	srv.AddContainer(api, "2026-10-01T12:00:00Z GET /health 200", "2026-10-01T12:00:01Z ERROR db timeout token=abc123", "2026-10-01T12:00:02Z GET /health 503")
	srv.AddContainer(ctr("bbbb2222", "shop-db-1", "exited", map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.service": "db"}))
	srv.AddContainer(ctr("cccc3333", "secret-vault", "running", map[string]string{"nodux.enable": "false"}))
	srv.AddContainer(ctr("dddd4444", "noisy", "running", nil))

	st := &dockerclient.Stats{}
	st.MemoryStats.Usage, st.MemoryStats.Limit = 300<<20, 512<<20
	st.CPUStats.CPUUsage.TotalUsage, st.CPUStats.SystemUsage, st.CPUStats.OnlineCPUs = 2_000_000, 10_000_000, 2
	st.PreCPUStats.CPUUsage.TotalUsage, st.PreCPUStats.SystemUsage = 1_000_000, 5_000_000
	st.CPUStats.ThrottlingData.Periods, st.CPUStats.ThrottlingData.ThrottledPeriods = 100, 40
	srv.SetStats("aaaa1111", st)
	srv.SetTop("aaaa1111", &dockerclient.Top{Titles: []string{"PID", "CMD"}, Processes: [][]string{{"1", "server --password=s3cret"}}})

	red, err := redact.New(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	tb := New(Config{
		Docker:   dockerclient.New(srv.SocketPath),
		Redactor: red,
		ProcPath: fakeProc(t),
		Exclude:  []string{"noisy"},
	})
	tb.cpuSample = 10 * time.Millisecond
	tb.now = func() time.Time { return time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC) }
	return tb, srv
}

func call(t *testing.T, tb *Toolbox, name string, input any) (string, error) {
	t.Helper()
	raw, _ := json.Marshal(input)
	return tb.Call(context.Background(), name, raw)
}

func mustCall(t *testing.T, tb *Toolbox, name string, input any) string {
	t.Helper()
	out, err := call(t, tb, name, input)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return out
}

func contains(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestTools_ListHidesExcluded(t *testing.T) {
	tb, _ := setup(t)
	out := mustCall(t, tb, "list_containers", nil)
	contains(t, out, "2 containers", "shop-api-1: running", "compose shop/api", "shop-db-1: exited")
	if strings.Contains(out, "secret-vault") || strings.Contains(out, "noisy") {
		t.Errorf("excluded containers listed:\n%s", out)
	}
	if _, err := call(t, tb, "inspect_container", map[string]string{"name": "secret-vault"}); err == nil {
		t.Error("a nodux.enable=false container could be inspected")
	}
}

func TestTools_ResolveNames(t *testing.T) {
	tb, _ := setup(t)
	for _, q := range []string{"shop-api-1", "/shop-api-1", "aaaa", "api"} {
		if c, err := tb.resolve(context.Background(), q); err != nil || c.ID != "aaaa1111" {
			t.Errorf("resolve(%q) = %v, %v", q, c.ID, err)
		}
	}
	if _, err := tb.resolve(context.Background(), "shop"); err == nil || !strings.Contains(err.Error(), "several") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := tb.resolve(context.Background(), "redis"); err == nil || !strings.Contains(err.Error(), "shop-api-1, shop-db-1") {
		t.Errorf("unknown: %v", err)
	}
}

func TestTools_InspectHidesSecrets(t *testing.T) {
	tb, _ := setup(t)
	out := mustCall(t, tb, "inspect_container", map[string]string{"name": "api"})
	contains(t, out,
		"name: shop-api-1 (id aaaa1111)", "image: shop-api-1:latest (feedface0123)", "created: 2026-10-01 11:48:00 UTC",
		"health: unhealthy, failing streak 2", "check exited 1: 503", "restart policy: always", "limits: memory 512.0MiB",
		"environment variables set (values hidden): DATABASE_URL, PORT", "mount: volume uploads -> /data (rw)",
		"labels: com.docker.compose.project=shop", "--password=[REDACTED]",
	)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "s3cret") {
		t.Errorf("secret leaked:\n%s", out)
	}
}

func TestTools_LogsRangeAndFilter(t *testing.T) {
	tb, srv := setup(t)
	for len(srv.LogQueries) > 0 {
		<-srv.LogQueries
	}
	out := mustCall(t, tb, "container_logs", map[string]any{"name": "api", "since": "15m", "until": "2026-10-01T12:10:00Z", "contains": "error"})
	contains(t, out, "1 log lines from shop-api-1", "ERROR db timeout token=[REDACTED]")
	q, _ := url.ParseQuery(<-srv.LogQueries)
	if q.Get("timestamps") != "true" || q.Get("since") != "1790856900.000000000" || q.Get("until") != "1790856600.000000000" || q.Get("tail") != "2000" {
		t.Errorf("log query = %v", q)
	}

	out = mustCall(t, tb, "container_logs", map[string]any{"name": "api", "tail": 1})
	contains(t, out, "1 log lines", "GET /health 503")
	if _, err := call(t, tb, "container_logs", map[string]any{"name": "api", "since": "yesterday-ish"}); err == nil {
		t.Error("bad time accepted")
	}
	if _, err := call(t, tb, "container_logs", map[string]any{}); err == nil {
		t.Error("missing name accepted")
	}
}

func TestTools_Stats(t *testing.T) {
	tb, _ := setup(t)
	out := mustCall(t, tb, "container_stats", map[string]string{"name": "api"})
	contains(t, out, "cpu: 40.0%", "memory: 300.0MiB of 512.0MiB limit (59%)", "cpu throttling: 40 of 100 periods", "server --password=[REDACTED]")
	out = mustCall(t, tb, "container_stats", map[string]string{"name": "db"})
	contains(t, out, "shop-db-1 is not running")
}

func TestTools_DiskUsage(t *testing.T) {
	tb, srv := setup(t)
	df := &dockerclient.DiskUsage{LayersSize: 3 << 30}
	df.Images = append(df.Images, struct {
		ID         string   `json:"Id"`
		RepoTags   []string `json:"RepoTags"`
		Size       int64    `json:"Size"`
		SharedSize int64    `json:"SharedSize"`
		Containers int64    `json:"Containers"`
	}{ID: "i1", RepoTags: []string{"<none>:<none>"}, Size: 1 << 30})
	srv.SetDiskUsage(df)
	out := mustCall(t, tb, "docker_disk_usage", nil)
	contains(t, out, "images: 1, 3.0GiB on disk; 1 used by no container (about 1.0GiB", "1 dangling", "build cache: 0B")
}

func TestTools_HostOverview(t *testing.T) {
	tb, _ := setup(t)
	tb.cfg.DiskPaths = []string{t.TempDir()}
	out := mustCall(t, tb, "host_overview", nil)
	contains(t, out,
		"uptime: 27h46m0s", "load average: 0.50 0.40 0.30 (2 CPUs)",
		"memory: 6.0GiB of 8.0GiB in use, 2.0GiB available; swap 512.0MiB of 1.0GiB in use",
		"pressure memory some: avg10=1.50 avg60=0.80", "% full",
		"top processes by memory:", "1.0GiB pid 42: postgres -D /var/lib/postgresql/data",
		"only 2 processes are visible",
	)
}

func TestTools_AlertHistory(t *testing.T) {
	tb, _ := setup(t)
	store, err := history.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := tb.now()
	store.AddAlerts(context.Background(), []history.Alert{
		{Time: now.Add(-time.Hour), State: "firing", Detector: "exit", Severity: "warning", Subject: "shop-api-1", Container: true, Message: "exited with code 1", IncidentID: 4},
		{Time: now.Add(-48 * time.Hour), State: "firing", Detector: "oom", Severity: "critical", Subject: "shop-api-1", Container: true, Message: "old"},
	})
	tb.cfg.History = store
	tb.cfg.OpenAlerts = func() []detector.Issue {
		return []detector.Issue{{Detector: "unhealthy", Container: detector.ContainerSnapshot{Name: "shop-api-1"}, Message: "healthcheck failing", DetectedAt: now.Add(-10 * time.Minute)}}
	}
	out := mustCall(t, tb, "alert_history", map[string]any{"name": "shop-api-1"})
	contains(t, out, "unhealthy shop-api-1, open for 10m0s: healthcheck failing", "firing exit shop-api-1: exited with code 1 [incident 4]")
	if strings.Contains(out, "old") {
		t.Errorf("default window is 24h:\n%s", out)
	}
	out = mustCall(t, tb, "alert_history", map[string]any{"hours": 72})
	contains(t, out, "oom shop-api-1: old")

	names := map[string]bool{}
	for _, s := range tb.Tools() {
		names[s.Name] = true
	}
	if !names["alert_history"] || len(names) != 7 {
		t.Errorf("tools = %v", names)
	}
}

func TestTools_Unknown(t *testing.T) {
	tb, _ := setup(t)
	if _, err := call(t, tb, "rm_rf", nil); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if _, err := tb.Call(context.Background(), "container_logs", json.RawMessage(`{"name":`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	for _, s := range tb.Tools() {
		if s.Name == "alert_history" {
			t.Error("alert_history offered without history or open alerts")
		}
	}
}

// fakeProc writes a minimal /proc with two processes.
func fakeProc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("uptime", "99960.12 1000.00\n")
	write("loadavg", "0.50 0.40 0.30 1/200 4242\n")
	write("stat", "cpu  1 2 3 4 5 6 7 8 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\ncpu1 1 1 1 1 1 1 1 1 0 0\nintr 0\n")
	write("meminfo", "MemTotal:       8388608 kB\nMemFree:  100 kB\nMemAvailable:   2097152 kB\nSwapTotal:      1048576 kB\nSwapFree:        524288 kB\n")
	write("pressure/memory", "some avg10=1.50 avg60=0.80 avg300=0.20 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	write("42/status", "Name:\tpostgres\nVmRSS:\t 1048576 kB\n")
	write("42/cmdline", "postgres\x00-D\x00/var/lib/postgresql/data\x00")
	write("42/stat", "42 (postgres) S 1 42 42 0 -1 4194560 100 0 0 0 500 100 0 0 20 0 1 0 100 1000 100\n")
	write("7/status", "Name:\tkthreadd\n")
	write("7/stat", "7 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n")
	return dir
}
