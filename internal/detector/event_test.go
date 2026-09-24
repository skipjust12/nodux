package detector

import (
	"strings"
	"testing"
)

func ev(id, action string, code int) ContainerEvent {
	return ContainerEvent{ID: id, Name: "app", Action: action, ExitCode: code}
}

func TestOOMDetector(t *testing.T) {
	d := NewOOMDetector()
	for _, action := range []string{"start", "kill", "die", "destroy"} {
		if issue := d.HandleEvent(ev("c1", action, 137)); issue != nil {
			t.Errorf("%s reported as OOM", action)
		}
	}
	issue := d.HandleEvent(ev("c1", "oom", 0))
	if issue == nil {
		t.Fatal("expected OOM issue")
	}
	if issue.Severity != SeverityCritical || !issue.Container.OOMKilled || issue.Container.Name != "app" {
		t.Errorf("unexpected issue: %+v", issue)
	}
}

// The event sequences below are what Docker 29 actually emits (checked
// against a live daemon).
func TestExitDetector(t *testing.T) {
	tests := []struct {
		name    string
		skipOOM bool
		events  []ContainerEvent
		want    string // substring of the message, "" = no issue
	}{
		{
			name:   "crash",
			events: []ContainerEvent{ev("c1", "start", 0), ev("c1", "die", 3)},
			want:   "code 3",
		},
		{
			name:   "clean exit ignored",
			events: []ContainerEvent{ev("c1", "start", 0), ev("c1", "die", 0)},
		},
		{
			name: "docker stop that escalated to SIGKILL",
			events: []ContainerEvent{
				ev("c1", "start", 0), ev("c1", "kill", 0), ev("c1", "kill", 0),
				ev("c1", "stop", 0), ev("c1", "die", 137),
			},
		},
		{
			name: "kill before a restart doesn't mask the next crash",
			events: []ContainerEvent{
				ev("c1", "kill", 0), ev("c1", "die", 143), ev("c1", "start", 0), ev("c1", "die", 1),
			},
			want: "code 1",
		},
		{
			name:    "OOM left to the oom detector",
			skipOOM: true,
			events:  []ContainerEvent{ev("c1", "start", 0), ev("c1", "oom", 0), ev("c1", "die", 137)},
		},
		{
			name:   "OOM reported here when the oom detector is off",
			events: []ContainerEvent{ev("c1", "start", 0), ev("c1", "oom", 0), ev("c1", "die", 137)},
			want:   "OOM killed",
		},
		{
			name:   "external SIGKILL",
			events: []ContainerEvent{ev("c1", "start", 0), ev("c1", "die", 137)},
			want:   "SIGKILL",
		},
		{
			name:   "segfault",
			events: []ContainerEvent{ev("c1", "die", 139)},
			want:   "segmentation fault",
		},
		{
			name:   "kill on another container doesn't mask this one",
			events: []ContainerEvent{ev("c2", "kill", 0), ev("c1", "die", 2)},
			want:   "code 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewExitDetector([]int{0}, tt.skipOOM)
			var got *Issue
			for _, e := range tt.events {
				if issue := d.HandleEvent(e); issue != nil {
					if got != nil {
						t.Fatalf("more than one issue: %+v", issue)
					}
					got = issue
				}
			}
			switch {
			case tt.want == "" && got != nil:
				t.Fatalf("unexpected issue: %+v", got)
			case tt.want != "" && got == nil:
				t.Fatalf("expected issue containing %q, got none", tt.want)
			case got != nil && !strings.Contains(got.Message, tt.want):
				t.Fatalf("message %q doesn't contain %q", got.Message, tt.want)
			}
		})
	}
}

func TestExitDetector_DestroyDropsState(t *testing.T) {
	d := NewExitDetector([]int{0}, true)
	d.HandleEvent(ev("c1", "kill", 0))
	d.HandleEvent(ev("c1", "destroy", 0))
	if len(d.killed) != 0 || len(d.oomed) != 0 {
		t.Fatalf("state not dropped: killed=%v oomed=%v", d.killed, d.oomed)
	}
}

func TestExitDetector_CustomIgnoreCodes(t *testing.T) {
	d := NewExitDetector([]int{0, 143}, true)
	if issue := d.HandleEvent(ev("c1", "die", 143)); issue != nil {
		t.Fatalf("ignored code reported: %+v", issue)
	}
}
