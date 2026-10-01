package incident

import (
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newGrouper(cfg Config) (*Grouper, *clock) {
	c := &clock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	g := New(cfg)
	g.now = c.now
	return g, c
}

func ctr(detectorName, name, project string) detector.Issue {
	i := detector.Issue{Detector: detectorName, Container: detector.ContainerSnapshot{ID: name + "-id", Name: name}, Logs: []string{"log"}}
	if project != "" {
		i.Container.Labels = map[string]string{detector.LabelComposeProject: project}
	}
	return i
}

func host(detectorName, resource string) detector.Issue {
	return detector.Issue{Detector: detectorName, Resource: resource}
}

var cfg = Config{Enabled: true, GroupWait: 30 * time.Second, Window: 10 * time.Minute}

func TestGrouper_BurstBecomesOneBatch(t *testing.T) {
	g, c := newGrouper(cfg)

	// Host memory first, then three containers fail: one incident.
	g.Add(host("host_memory", "memory"))
	c.t = c.t.Add(5 * time.Second)
	g.Add(ctr("oom", "api", ""))
	g.Add(ctr("oom", "worker", ""))
	g.Add(ctr("crashloop", "api", ""))

	if got := g.Due(c.t); len(got) != 0 {
		t.Fatalf("sent before group_wait: %+v", got)
	}
	if next := g.Next(); !next.Equal(c.t.Add(25 * time.Second)) {
		t.Errorf("next = %v", next)
	}
	c.t = c.t.Add(25 * time.Second)
	got := g.Due(c.t)
	if len(got) != 1 || len(got[0].Alerts) != 4 || got[0].Update || got[0].IncidentID != 1 {
		t.Fatalf("batches = %+v", got)
	}
	for _, a := range got[0].Alerts {
		if a.IncidentID != 1 {
			t.Errorf("alert not tagged: %+v", a)
		}
	}
	if !g.Next().IsZero() {
		t.Error("nothing should be pending")
	}
}

func TestGrouper_HostAlertJoinsContainerIncident(t *testing.T) {
	g, c := newGrouper(cfg)
	g.Add(ctr("oom", "api", ""))
	g.Due(c.t.Add(time.Minute))
	g.SetSummary(1, "api leaks memory")

	// host_memory fires minutes later (it waits for for_seconds).
	c.t = c.t.Add(5 * time.Minute)
	g.Add(host("host_memory", "memory"))
	c.t = c.t.Add(time.Minute)
	got := g.Due(c.t)
	if len(got) != 1 || got[0].IncidentID != 1 || !got[0].Update {
		t.Fatalf("batches = %+v", got)
	}
	if len(got[0].Earlier) != 1 || got[0].Earlier[0].Container.Name != "api" || got[0].Earlier[0].Logs != nil || got[0].PrevSummary != "api leaks memory" {
		t.Errorf("update context = %+v", got[0])
	}
}

func TestGrouper_UnrelatedContainersStaySeparate(t *testing.T) {
	g, c := newGrouper(cfg)
	g.Add(ctr("exit", "api", "shop"))
	g.Add(ctr("exit", "blog", "blog"))
	g.Add(ctr("exit", "db", "shop")) // same compose project as api
	c.t = c.t.Add(time.Minute)
	got := g.Due(c.t)
	if len(got) != 2 {
		t.Fatalf("batches = %+v", got)
	}
	sizes := map[int64]int{got[0].IncidentID: len(got[0].Alerts), got[1].IncidentID: len(got[1].Alerts)}
	if sizes[1] != 2 || sizes[2] != 1 {
		t.Errorf("grouping = %v", sizes)
	}
}

func TestGrouper_WindowClosesIncident(t *testing.T) {
	g, c := newGrouper(cfg)
	g.Add(ctr("exit", "api", ""))
	c.t = c.t.Add(time.Minute)
	g.Due(c.t)
	c.t = c.t.Add(11 * time.Minute)
	g.Add(ctr("exit", "api", ""))
	c.t = c.t.Add(time.Minute)
	got := g.Due(c.t)
	if len(got) != 1 || got[0].IncidentID != 2 || got[0].Update {
		t.Fatalf("a quiet window should start a new incident: %+v", got)
	}
}

func TestGrouper_ResolutionsFollowTheirIncident(t *testing.T) {
	g, c := newGrouper(cfg)
	firing := ctr("unhealthy", "api", "")
	firing.Key = "unhealthy/api-id"
	g.Add(firing)
	c.t = c.t.Add(time.Minute)
	g.Due(c.t)

	// Resolved while the incident is open: an update of incident 1.
	res := firing
	res.Resolved = true
	g.Add(res)
	c.t = c.t.Add(time.Minute)
	got := g.Due(c.t)
	if len(got) != 1 || got[0].IncidentID != 1 || !got[0].Update || !got[0].Alerts[0].Resolved || got[0].Firing() {
		t.Fatalf("batches = %+v", got)
	}

	// A resolution for an incident that has closed goes out on its own,
	// right away, still tagged with the incident.
	firing.Key = "unhealthy/db-id"
	firing.Container.Name = "db"
	g.Add(firing)
	c.t = c.t.Add(time.Minute)
	g.Due(c.t)
	c.t = c.t.Add(time.Hour)
	res = firing
	res.Resolved = true
	g.Add(res)
	got = g.Due(c.t)
	if len(got) != 1 || got[0].IncidentID != 2 || got[0].Alerts[0].IncidentID != 2 {
		t.Fatalf("late resolution = %+v", got)
	}

	// A resolution nobody knows about (no key) is sent alone, ungrouped.
	g.Add(detector.Issue{Detector: "docker", Resource: "daemon", Resolved: true})
	if got := g.Due(c.t); len(got) != 1 || got[0].IncidentID != 0 {
		t.Fatalf("unknown resolution = %+v", got)
	}
}

func TestGrouper_Disabled(t *testing.T) {
	g, c := newGrouper(Config{})
	g.Add(ctr("exit", "api", ""))
	g.Add(ctr("exit", "api", ""))
	if !g.Next().Equal(c.t) {
		t.Error("disabled grouper should be due immediately")
	}
	got := g.Due(c.t)
	if len(got) != 2 || got[0].IncidentID != 0 || len(got[0].Alerts) != 1 {
		t.Fatalf("batches = %+v", got)
	}
}

func TestGrouper_FlushAndState(t *testing.T) {
	g, _ := newGrouper(cfg)
	a := ctr("unhealthy", "api", "")
	a.Key = "unhealthy/api-id"
	g.Add(a)
	if got := g.Flush(); len(got) != 1 {
		t.Fatalf("flush = %+v", got)
	}

	data, err := g.SaveState()
	if err != nil {
		t.Fatal(err)
	}
	g2, c2 := newGrouper(cfg)
	if err := g2.LoadState(data); err != nil {
		t.Fatal(err)
	}
	g2.Add(ctr("exit", "blog", ""))
	res := a
	res.Resolved = true
	g2.Add(res)
	got := g2.Due(c2.t.Add(time.Minute))
	ids := map[int64]bool{}
	for _, b := range got {
		ids[b.IncidentID] = true
	}
	if !ids[1] || !ids[2] {
		t.Fatalf("restored counter or episode map lost: %+v", got)
	}
}
