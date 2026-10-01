package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/skipjust12/nodux/internal/engine"
)

// metrics writes the Prometheus text exposition format by hand: a dozen
// series don't justify a client library.
func (src *Source) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m := &metricWriter{w: w}

	m.family("nodux_build_info", "gauge", "Always 1; the version label says which nodux is running.")
	m.sample("nodux_build_info", 1, "version", src.Version)
	m.family("nodux_start_time_seconds", "gauge", "When nodux started, in Unix seconds.")
	m.sample("nodux_start_time_seconds", float64(src.Started.Unix()))

	m.family("nodux_docker_up", "gauge", "1 if the last poll of the Docker daemon worked.")
	m.sample("nodux_docker_up", boolf(src.Engine.Healthy()))
	m.family("nodux_healthy", "gauge", "1 if /healthz reports ok.")
	m.sample("nodux_healthy", boolf(src.unhealthy() == ""))
	if last := src.Engine.LastPoll(); !last.IsZero() {
		m.family("nodux_last_poll_timestamp_seconds", "gauge", "When the Docker daemon was last polled successfully.")
		m.sample("nodux_last_poll_timestamp_seconds", float64(last.UnixMilli())/1000)
	}

	type epKey struct{ detector, severity string }
	episodes := map[epKey]int{}
	silenced := 0
	for _, ep := range src.Engine.Episodes() {
		episodes[epKey{ep.Detector, ep.Severity}]++
		if ep.Silenced {
			silenced++
		}
	}
	m.family("nodux_active_episodes", "gauge", "Open problems (alerted, not resolved yet), by detector and severity.")
	keys := make([]epKey, 0, len(episodes))
	for k := range episodes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].detector+"/"+keys[i].severity < keys[j].detector+"/"+keys[j].severity
	})
	for _, k := range keys {
		m.sample("nodux_active_episodes", float64(episodes[k]), "detector", k.detector, "severity", k.severity)
	}
	m.family("nodux_silenced_episodes", "gauge", "Open problems whose alert is held back by a silence.")
	m.sample("nodux_silenced_episodes", float64(silenced))

	counts := src.Engine.AlertCounts()
	ckeys := make([]engine.AlertKey, 0, len(counts))
	for k := range counts {
		ckeys = append(ckeys, k)
	}
	sort.Slice(ckeys, func(i, j int) bool { return fmt.Sprint(ckeys[i]) < fmt.Sprint(ckeys[j]) })
	m.family("nodux_alerts_total", "counter", "Alerts and resolutions dispatched since startup.")
	for _, k := range ckeys {
		m.sample("nodux_alerts_total", float64(counts[k]),
			"detector", k.Detector, "severity", k.Severity, "state", k.State, "silenced", strconv.FormatBool(k.Silenced))
	}

	m.family("nodux_notifications_total", "counter", "Deliveries to each receiver, by result (sent, failed after retries, dropped because the queue was full).")
	for _, r := range src.Receivers {
		s := r.Stats()
		m.sample("nodux_notifications_total", float64(s.Sent), "receiver", r.Name(), "result", "sent")
		m.sample("nodux_notifications_total", float64(s.Failed), "receiver", r.Name(), "result", "failed")
		m.sample("nodux_notifications_total", float64(s.Dropped), "receiver", r.Name(), "result", "dropped")
	}
	m.family("nodux_notification_queue_length", "gauge", "Alerts waiting to be delivered, per receiver.")
	for _, r := range src.Receivers {
		m.sample("nodux_notification_queue_length", float64(r.Stats().Pending), "receiver", r.Name())
	}

	if src.Silences != nil {
		m.family("nodux_silences", "gauge", "Active silences set by hand.")
		m.sample("nodux_silences", float64(len(src.Silences.List())))
		m.family("nodux_deploy_windows", "gauge", "Open automatic deploy windows (containers and compose projects).")
		m.sample("nodux_deploy_windows", float64(len(src.Silences.Windows())))
	}

	if src.LLM != nil {
		u := src.LLM.Usage()
		if u.MaxPerHour > 0 {
			m.family("nodux_llm_budget_remaining", "gauge", "LLM calls left in the current hourly budget.")
			m.sample("nodux_llm_budget_remaining", float64(u.Remaining))
			m.family("nodux_llm_budget_per_hour", "gauge", "The hourly LLM call budget.")
			m.sample("nodux_llm_budget_per_hour", float64(u.MaxPerHour))
		}
		m.family("nodux_llm_requests_total", "counter", "LLM classifications by result (ok, failed, over_budget: skipped because the budget was spent).")
		m.sample("nodux_llm_requests_total", float64(u.OK), "result", "ok")
		m.sample("nodux_llm_requests_total", float64(u.Failed), "result", "failed")
		m.sample("nodux_llm_requests_total", float64(u.OverBudget), "result", "over_budget")
	}
}

type metricWriter struct{ w io.Writer }

func (m *metricWriter) family(name, typ, help string) {
	fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// sample writes one series; labels are name/value pairs.
func (m *metricWriter) sample(name string, v float64, labels ...string) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%s=\"%s\"", labels[i], labelEscaper.Replace(labels[i+1]))
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(m.w, "%s %s\n", b.String(), strconv.FormatFloat(v, 'g', -1, 64))
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
