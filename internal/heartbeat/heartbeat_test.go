package heartbeat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeartbeat_PingsOnlyWhileHealthy(t *testing.T) {
	var pings atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/ping/uuid" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		pings.Add(1)
	}))
	defer srv.Close()

	var healthy atomic.Bool
	h := New(srv.URL+"/ping/uuid", 10*time.Millisecond, healthy.Load)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(ctx)
	}()

	time.Sleep(60 * time.Millisecond)
	if n := pings.Load(); n != 0 {
		t.Fatalf("pinged %d times while unhealthy", n)
	}
	healthy.Store(true)
	time.Sleep(60 * time.Millisecond)
	if n := pings.Load(); n < 2 {
		t.Fatalf("pinged %d times while healthy", n)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run didn't stop on cancel")
	}
}

func TestHeartbeat_PingErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	h := New(srv.URL, time.Second, func() bool { return true })
	if err := h.ping(context.Background()); err == nil {
		t.Fatal("expected an error for a 404")
	}
}
