package silence

import (
	"testing"
	"time"
)

func TestParseMatcher(t *testing.T) {
	for in, want := range map[string]Matcher{
		"api":                           {Target: "api"},
		"all":                           {Target: "*"},
		"/var/lib/docker":               {Target: "/var/lib/docker"},
		"detector=memory,container=a-*": {Detector: "memory", Container: "a-*"},
		"project=shop":                  {Project: "shop"},
	} {
		got, err := ParseMatcher(in)
		if err != nil || got != want {
			t.Errorf("ParseMatcher(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "color=red", "detector=", "container=[", "a,b"} {
		if _, err := ParseMatcher(bad); err == nil {
			t.Errorf("ParseMatcher(%q): expected an error", bad)
		}
	}
	if (Matcher{}).Matches(Subject{Container: "x"}) {
		t.Error("an empty matcher must match nothing")
	}
}

func TestMatcher(t *testing.T) {
	api := Subject{Detector: "memory", Container: "api-1", Project: "shop"}
	disk := Subject{Detector: "host_disk", Resource: "/var/lib/docker"}
	tests := []struct {
		m         Matcher
		api, disk bool
	}{
		{Matcher{Target: "*"}, true, true},
		{Matcher{Target: "api-*"}, true, false},
		{Matcher{Target: "/var/lib/docker"}, false, true},
		{Matcher{Detector: "host_*"}, false, true},
		{Matcher{Detector: "memory", Container: "api-2"}, false, false},
		{Matcher{Project: "shop"}, true, false},
	}
	for _, tt := range tests {
		if got := tt.m.Matches(api); got != tt.api {
			t.Errorf("%v matches api = %v", tt.m, got)
		}
		if got := tt.m.Matches(disk); got != tt.disk {
			t.Errorf("%v matches disk = %v", tt.m, got)
		}
	}
}

func TestStore(t *testing.T) {
	st := New()
	now := time.Now()
	st.now = func() time.Time { return now }

	s, err := st.Add(Matcher{Target: "api"}, 30*time.Minute, "migrating")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Add(Matcher{}, time.Minute, ""); err == nil {
		t.Error("empty matcher accepted")
	}
	if _, err := st.Add(Matcher{Target: "x"}, 0, ""); err == nil {
		t.Error("zero duration accepted")
	}
	if reason, ok := st.Silenced(Subject{Container: "api"}); !ok || reason != "silence "+s.ID {
		t.Fatalf("not silenced: %q %v", reason, ok)
	}
	if _, ok := st.Silenced(Subject{Container: "db"}); ok {
		t.Fatal("db silenced")
	}

	st.Deploy("web-1", "shop", now.Add(2*time.Minute))
	if reason, ok := st.Silenced(Subject{Container: "worker", Project: "shop"}); !ok || reason != "deploy of compose project shop" {
		t.Fatalf("project window: %q %v", reason, ok)
	}
	if _, ok := st.Silenced(Subject{Container: "web-1"}); !ok {
		t.Fatal("container window")
	}
	if _, ok := st.Silenced(Subject{Container: "web-1", Project: "shop", OneOff: true}); ok {
		t.Fatal("deploy windows must not swallow one-off alerts (crashes, OOM kills)")
	}
	if _, ok := st.Silenced(Subject{Container: "api", OneOff: true}); !ok {
		t.Fatal("manual silences apply to one-off alerts too")
	}
	if len(st.Windows()) != 2 || len(st.List()) != 1 {
		t.Fatalf("windows %v, silences %v", st.Windows(), st.List())
	}

	now = now.Add(5 * time.Minute)
	if _, ok := st.Silenced(Subject{Container: "web-1", Project: "shop"}); ok {
		t.Fatal("deploy window should have closed")
	}
	if !st.Remove(s.ID) || st.Remove(s.ID) {
		t.Fatal("remove")
	}
	if _, ok := st.Silenced(Subject{Container: "api"}); ok {
		t.Fatal("removed silence still applies")
	}

	st.Add(Matcher{Target: "*"}, time.Minute, "")
	now = now.Add(time.Minute)
	if len(st.List()) != 0 {
		t.Fatal("expired silence still listed")
	}
	var nilStore *Store
	if _, ok := nilStore.Silenced(Subject{Container: "x"}); ok {
		t.Fatal("nil store silences")
	}
}
