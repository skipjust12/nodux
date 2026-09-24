package dockerclient_test

import (
	"context"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/dockerclient"
	"github.com/skipjust12/nodux/internal/dockertest"
)

func TestClient_ListInspectLogs(t *testing.T) {
	srv := dockertest.New(t)
	c := &dockerclient.ContainerInspect{ID: "abc", Name: "/web"}
	c.State.Status = "running"
	c.State.Health = &dockerclient.Health{Status: "unhealthy", FailingStreak: 2}
	srv.AddContainer(c, "line one", "", "line two")

	cl := dockerclient.New(srv.SocketPath)
	ctx := context.Background()

	if err := cl.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	list, err := cl.ListContainers(ctx)
	if err != nil || len(list) != 1 || list[0].Names[0] != "/web" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	got, err := cl.InspectContainer(ctx, "abc")
	if err != nil || got.State.Health == nil || got.State.Health.Status != "unhealthy" {
		t.Fatalf("inspect = %+v, %v", got, err)
	}
	logs, err := cl.ContainerLogs(ctx, "abc", 20, false)
	if err != nil || !reflect.DeepEqual(logs, []string{"line one", "line two"}) {
		t.Fatalf("logs = %q, %v", logs, err)
	}

	_, err = cl.InspectContainer(ctx, "missing")
	if err == nil || !dockerclient.IsGone(err) {
		t.Fatalf("missing container: want IsGone error, got %v", err)
	}
}

func TestClient_PingUnreachableSocket(t *testing.T) {
	cl := dockerclient.New("/nonexistent/docker.sock")
	err := cl.Ping(context.Background())
	if err == nil {
		t.Fatal("expected error for missing socket")
	}
	if dockerclient.IsGone(err) {
		t.Fatal("a dead socket must not look like a removed container")
	}
}

func TestClient_Events(t *testing.T) {
	srv := dockertest.New(t)
	stream := srv.NewStream()
	stream <- dockerclient.Event{Type: "container", Action: "die", Actor: dockerclient.Actor{ID: "abc", Attributes: map[string]string{"exitCode": "3"}}}
	close(stream)

	cl := dockerclient.New(srv.SocketPath)
	since := time.Unix(1700000000, 5)
	var got []dockerclient.Event
	err := cl.Events(context.Background(), since, []string{"die", "oom"}, func(ev dockerclient.Event) {
		got = append(got, ev)
	})
	if err == nil {
		t.Fatal("expected an error when the daemon closes the stream")
	}
	if len(got) != 1 || got[0].Action != "die" || got[0].Actor.Attributes["exitCode"] != "3" {
		t.Fatalf("events = %+v", got)
	}

	q, _ := url.ParseQuery(<-srv.EventQueries)
	if q.Get("since") != "1700000000.000000005" {
		t.Errorf("since = %q", q.Get("since"))
	}
	if f := q.Get("filters"); f != `{"event":["die","oom"],"type":["container"]}` {
		t.Errorf("filters = %q", f)
	}
}

func TestClient_EventsStopsOnCancel(t *testing.T) {
	srv := dockertest.New(t)
	srv.NewStream() // never closed

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- dockerclient.New(srv.SocketPath).Events(ctx, time.Time{}, []string{"die"}, func(dockerclient.Event) {})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected ctx error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Events didn't return after cancel")
	}
}

func TestClient_Stats(t *testing.T) {
	srv := dockertest.New(t)
	for name, tc := range map[string]struct {
		stats map[string]uint64
		want  uint64
	}{
		"cgroup v1":              {map[string]uint64{"total_inactive_file": 100, "inactive_file": 999}, 900},
		"cgroup v2":              {map[string]uint64{"inactive_file": 300}, 700},
		"no stats":               {nil, 1000},
		"inactive exceeds usage": {map[string]uint64{"inactive_file": 5000}, 0},
	} {
		st := &dockerclient.Stats{}
		st.MemoryStats.Usage = 1000
		st.MemoryStats.Limit = 4096
		st.MemoryStats.Stats = tc.stats
		srv.SetStats("abc", st)

		got, err := dockerclient.New(srv.SocketPath).ContainerStats(context.Background(), "abc")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.MemoryUsed() != tc.want || got.MemoryStats.Limit != 4096 {
			t.Errorf("%s: used = %d, want %d (limit %d)", name, got.MemoryUsed(), tc.want, got.MemoryStats.Limit)
		}
	}
}
