# nodux

A lightweight self-hosted AIOps daemon for VPS boxes running
Docker/Podman: it detects common container and host problems with plain
deterministic logic (`docker inspect`, the daemon's event stream, exit
codes, healthchecks, `/proc`, `statfs`, HTTP/TCP/TLS probes) and sends
alerts to stdout and to receivers routed by severity: Telegram, ntfy,
and webhooks (Slack, Mattermost, Discord, anything that takes JSON). An
optional LLM layer adds a short probable-cause note to container alerts.

## Detectors

| Detector      | Source         | Severity | Fires when |
|---------------|----------------|----------|------------|
| `crashloop`   | events + poll  | critical | a container was restarted after a crash `restart_threshold` times within `window_minutes` |
| `unhealthy`   | events + poll  | warning  | a running container's `HEALTHCHECK` reports `unhealthy` (includes the last check's output) |
| `oom`         | events         | critical | the kernel OOM killer hit the container's memory limit |
| `exit`        | events         | warning  | the main process exited with a non-zero code on its own (crash, segfault, external `kill -9`) |
| `memory`      | poll           | warning  | memory usage stays ≥ `threshold_percent` of the container's limit for `for_seconds`: the early warning before `oom` |
| `cpu_throttle`| poll           | warning  | a container with a CPU limit is throttled in ≥ `threshold_percent` of its scheduling periods for `for_seconds` |
| `expected`    | poll           | critical | a container listed in `detectors.expected.containers` doesn't exist or isn't running |
| `host_disk`   | host           | critical | a filesystem is ≥ `threshold_percent` full, by space or inodes |
| `host_disk_forecast` | host    | warning  | at the current fill rate a filesystem will be full within `horizon_hours` ("/ will be full in ~6h") |
| `host_memory` | host           | warning  | host memory in use (MemTotal − MemAvailable) stays ≥ threshold for `for_seconds` |
| `host_cpu`    | host           | warning  | host CPU busy time stays ≥ threshold for `for_seconds` |
| `host_pressure` | host         | warning  | a PSI signal from `/proc/pressure` (memory some, io full, …) stays ≥ its threshold for `for_seconds` |
| `host_oom`    | host + events  | critical | the kernel OOM killer killed something outside any container |
| `probe`       | probes         | critical | an HTTP, TCP or TLS probe failed `failures` times in a row |
| `tls_cert`    | probes         | warning → critical | a certificate seen by a probe expires within `cert_warn_days` (critical within `cert_critical_days`) |
| `docker`      | poll           | critical | the Docker daemon has been unreachable for `down_alert_after_seconds` |

Everything is on by default; an empty config file is a valid config.

### Alerts and resolutions

`oom` and `exit` report one-off events. The same detector won't alert
twice on the same container name within `alert_cooldown_minutes`
(default 10), so a crash-looping container gives you one `exit` alert,
not one per restart.

`host_oom` is one-off too, at most one alert per cooldown, each
carrying the count of every kill since the last one.

Everything else tracks a state that starts and ends. You get one alert
when the problem starts and one `"state": "resolved"` message when it
ends, for example `resolved after 12m (was: healthcheck failing …)`,
or `container removed after 3m` if the container is deleted in the
meantime. Threshold detectors (`memory`, `cpu_throttle`, `host_*`) only
resolve once the value drops 5 points below the threshold (half the
threshold, for thresholds under 10), so something hovering at the line
doesn't flap. If an open problem gets more severe (a certificate going
from 10 days left to 2), you get a second alert at the new severity.

### Why two sources

Some failures are gone by the next poll. With a restart policy, Docker
clears `State.OOMKilled` on the very next start, so an OOM in a
restarting container is effectively invisible to polling. It's only
reliable as an `oom` event. The same stream tells crashes apart from
intentional stops: `docker stop` / `kill` / `restart` / `rm -f` /
`compose down` all emit `kill` events before `die`, and a crash is a
bare `die`. So `exit` never fires on manual stops, and `crashloop`
doesn't count manual restarts. A `kill` with a signal the process is
meant to survive (`docker kill -s HUP` to reload nginx) doesn't count
as a stop: nodux compares the signal with the container's configured
stop signal.

`crashloop` counts restarts from those events, with exact timestamps,
and fires the moment the threshold is crossed. The poll keeps the
episode open until the container has run for a whole window without
restarting. A container whose restart policy gave up stays in the
episode, since it's still broken.

`unhealthy` works the same way: Docker emits `health_status: unhealthy`
the moment a healthcheck flips, so the alert doesn't wait for the next
poll. The event carries no healthcheck output, so nodux inspects the
container before alerting; the poll closes the episode once it's
healthy again.

`memory` measures usage the way `docker stats` does (minus reclaimable
page cache), only for containers started with a memory limit. Without
one, the "limit" is the host's RAM, which is what `host_memory` checks.

`unhealthy` ignores stopped containers: Docker marks a container with a
healthcheck `unhealthy` when it stops, even on a plain `docker stop`.

`cpu_throttle` reads `cpu_stats.throttling_data` from the same stats
call as `memory` (one call per container that needs either), and takes
the ratio of throttled to total CFS periods between polls. A container
pinned at its `--cpus` limit is the classic "slow but not crashing":
no exit, no OOM, healthchecks may even pass. Only containers with a CPU
limit are checked.

## Host checks

- **Pressure (PSI).** "CPU ≥ 95% for ten minutes" is a coarse signal.
  `/proc/pressure/{memory,io,cpu}` measures the damage directly: the
  share of the last minute (`avg60`) in which some (or all) tasks were
  stalled waiting for a resource. `memory some` catches thrashing
  (reclaim, swap-in, refaults) well before the OOM killer shows up;
  `io full` means every runnable task was waiting on I/O at once, which
  is a dying disk or a noisy neighbour on shared VPS storage. Defaults:
  `memory_some_percent: 10`, `io_full_percent: 10`; the other signals
  are off until you set a threshold. Needs Linux 4.20+ with PSI (some
  distro kernels need `psi=1` on the kernel command line); without it
  nodux logs once and moves on.
- **Host OOM.** The `oom` detector only sees Docker's events. The
  kernel counts every OOM kill in `/proc/vmstat` (`oom_kill`), container
  ones included, so `host_oom` matches the counter against container
  `oom` events (excluded containers' too) and reports the kills nobody
  claims after a settle window of `max(2 × poll interval, 30s)`: sshd,
  a database installed from packages, dockerd itself, or a systemd unit
  hitting its `MemoryMax=`. While the Docker event stream is down,
  container OOMs can't be told apart and may be reported here.
- **Disk forecast.** A static 90% on a 20 GB disk is 2 GB of headroom,
  which json-file logs can eat overnight. `host_disk_forecast` fits a
  least-squares line through the free space of the last `window_minutes`
  and alerts when the projected time to full is under `horizon_hours`:
  `disk / will be full in ~6h at the current rate (2.1GiB free, filling
  at 350.0MiB/h over the last 60m)`. It needs a quarter of the window of
  samples before it says anything, and the episode ends once the
  projection is back over twice the horizon.

## Probes

For a container without a `HEALTHCHECK`, a probe is the only way to
know the service actually answers:

```yaml
probes:
  targets:
    - {name: api, url: "http://127.0.0.1:8080/healthz", container: api}
    - {name: site, url: "https://example.com/"}
    - {name: postgres, tcp: "127.0.0.1:5432"}
    - {name: mail, tls: "mail.example.com:465"}
```

Probes run on their own loop (`interval_seconds`, default 30), all
targets in parallel, so a slow target never holds up the rest of nodux.
A probe alerts after `failures` failed checks in a row (default 2). An
HTTP probe is a GET that doesn't follow redirects and accepts any
2xx/3xx unless `status` says otherwise; a `tcp` probe connects; a `tls`
probe completes a verified handshake. Probes go direct, never through
`HTTPS_PROXY`. With `container:` set, the alert carries that
container's state and logs, and goes through the LLM layer like any
container alert. Messages show the URL without credentials or query
string.

Every `https` and `tls` probe also records the certificate chain, even
when verification fails, so `tls_cert` warns `cert_warn_days` (14)
before expiry and escalates to critical `cert_critical_days` (3)
before. It watches whichever certificate in the verified chain expires
first, intermediates included, and keeps reporting from the last
certificate it saw while the target is down. An expired or otherwise
invalid certificate also fails the probe itself. `tls_skip_verify:
true` accepts self-signed certificates and still tracks their expiry.

## Receivers and routing

```yaml
actions:
  receivers:
    - name: oncall
      type: telegram
      bot_token: ${NODUX_TELEGRAM_TOKEN}
      chat_id: "-1001234567890"
      severities: [critical]
    - name: phone
      type: ntfy
      url: https://ntfy.sh/${NODUX_NTFY_TOPIC}
      severities: [critical]
    - name: team
      type: webhook
      url: https://hooks.slack.com/services/${NODUX_SLACK_PATH}
      format: slack
      severities: [warning]
```

Each receiver gets the alerts its route lets through: `severities`
(empty = both), `detectors` (globs like `host_*`, empty = all) and
`send_resolved` (default true). A resolution goes where its alert went.

- **telegram** sends through the Bot API as HTML: headline, message,
  the analysis as a quote, the last log lines in a code block, under the
  4096-character limit. Resolutions arrive without a notification
  sound. `thread_id` posts into a forum topic, `api_url` points at a
  self-hosted Bot API server.
- **ntfy** publishes to `url` (`https://ntfy.sh/<topic>` or your own
  server; on ntfy.sh the topic name is effectively the password, so keep
  it in an environment variable). Critical alerts go out at priority 5,
  which breaks through do-not-disturb on phones; warnings at the default
  priority; resolutions at low priority. `token` is for protected
  topics.
- **webhook** is the generic one: `format: json` POSTs the full alert
  record, `format: slack` POSTs `{"text": …}`, which Slack, Mattermost,
  Rocket.Chat and Discord (`/slack` endpoint) all accept.

Every receiver delivers from its own background queue with retries (3
attempts on network errors, 5xx and 429) and is drained on shutdown.
The old single `actions.webhook` block still works and gets everything.

## Silences and deploys

```sh
nodux silence api 30m                              # container or resource "api"
nodux silence detector=memory,container=api 2h     # combine with key=value
nodux silence project=shop 1d -c "migrating the db"
nodux silence 'api-*' 1h                           # globs
nodux silence all 15m                              # everything
nodux silences                                     # list
nodux unsilence 3f9c2a1b                           # end one early
```

Keys are `detector`, `container`, `project` (compose project), `resource`
and `target` (a bare word: container name or resource, like `/` for
`host_disk`). Durations take Go syntax plus days (`2d`).

Deploys silence themselves: create, stop and remove events for a
container (`compose up`, `docker run`, `docker stop`, `docker rm`) open
a window covering that container and the rest of its compose project
until `silences.deploy_grace_seconds` (120) after the last such event,
so a probe failing while compose recreates the container doesn't page
anyone.

A silenced alert is still tracked and still printed to stdout (with
`"silenced": true`), just not sent to receivers or the LLM. If the
problem is still there when the silence or window ends, its alert goes
out then, marked `held back by a silence`; if it went away in the
meantime, you hear nothing about it. Deploy windows only hold back
ongoing problems: a container that crashes or gets OOM-killed right
after a deploy is reported immediately, since a deploy doesn't cause
crashes, and a one-off alert held back would be lost. Manual silences
apply to everything. Silences live in memory, so restarting nodux
clears them.

## What leaves the host

- **Redaction.** Before an alert goes to a webhook or the LLM, its
  message and log lines are scrubbed: `password=…`, `token: …`, bearer
  tokens, `user:pass@` in URLs, AWS/GitHub/Slack/`sk-…` keys. Add your
  own patterns under `redact.patterns`. Log lines are also cut at 1000
  bytes.
- **Secrets in config.** Receiver URLs, headers, Telegram bot tokens
  and chat IDs, ntfy tokens, probe URLs, the heartbeat URL and the LLM
  key can reference environment variables (`${NODUX_SLACK_PATH}`). An
  unset or empty variable is a startup error rather than a silently
  broken URL. Receiver and heartbeat URLs never appear in nodux's own
  logs (only scheme and host), because for Slack, Discord or a Telegram
  bot the URL is the credential; probe URLs appear in alerts without
  credentials or query string.
- **Hostname.** Every alert carries `host`, so alerts from several
  servers in one channel can be told apart.

## Watching nodux itself

- `docker` alerts when the daemon stops answering, and resolves when it
  comes back. Host checks keep running in the meantime.
- `heartbeat` pings a dead man's switch (healthchecks.io, an Uptime Kuma
  push monitor, …) every `interval_seconds` while nodux can reach the
  daemon. If nodux dies or loses Docker, the pings stop and that service
  alerts you from outside the box.
- `nodux status` shows what's going on right now, without grepping the
  journal:

  ```
  nodux v1.4.0 on vps1, up 3h12m; docker up, last poll 4s ago

  OPEN PROBLEMS
    SEVERITY  DETECTOR   SUBJECT  FOR  MESSAGE
    critical  crashloop  api      12m  container restarted 3 times in the last 5m0s after crashing
    critical  host_disk  /        1h   disk / at 91% (18.2GiB used, 1.8GiB free) [silenced]

  SILENCES
    ID        MATCH  ENDS IN  COMMENT
    3f9c2a1b  /      28m      cleaning up images

  RECEIVERS
    NAME    SENT  FAILED  DROPPED  QUEUED
    oncall  12    0       0        0

  LLM: 27 of 30 calls left this hour; 3 ok, 0 failed, 0 skipped over budget
  ```

  `--json` prints the raw status. The CLI talks to the daemon over the
  control socket (`server.socket_path`, default `/run/nodux/nodux.sock`,
  mode 0660); pass `--socket` or set `NODUX_SOCKET` if it's elsewhere.
- `server.listen: 127.0.0.1:9321` serves `/metrics` (Prometheus) and
  `/healthz` over TCP. `/healthz` is 200 `ok`, or 503 with the reason
  when the Docker daemon is unreachable or the poll loop has stopped
  making progress. The metrics:

  | Metric | Type | |
  |---|---|---|
  | `nodux_active_episodes{detector,severity}` | gauge | open problems |
  | `nodux_silenced_episodes` | gauge | open problems held back by a silence |
  | `nodux_alerts_total{detector,severity,state,silenced}` | counter | alerts and resolutions dispatched |
  | `nodux_notifications_total{receiver,result}` | counter | deliveries: `sent`, `failed` (after retries), `dropped` (queue full) |
  | `nodux_notification_queue_length{receiver}` | gauge | alerts waiting to be delivered |
  | `nodux_llm_budget_remaining`, `nodux_llm_budget_per_hour` | gauge | the hourly LLM budget |
  | `nodux_llm_requests_total{result}` | counter | `ok`, `failed`, `over_budget` |
  | `nodux_silences`, `nodux_deploy_windows` | gauge | active silences and deploy windows |
  | `nodux_docker_up`, `nodux_healthy` | gauge | 1/0 |
  | `nodux_last_poll_timestamp_seconds`, `nodux_start_time_seconds`, `nodux_build_info{version}` | gauge | |

  The silence API is only served on the unix socket, never on the TCP
  listener: whoever can silence alerts can hide a problem, so that's
  left to file permissions. `/metrics` and `/healthz` are on the socket
  too (`curl --unix-socket /run/nodux/nodux.sock http://x/metrics`).

## LLM layer (optional)

With `llm.enabled: true`, container alerts are sent to Claude together
with their redacted logs before they go out, and the reply lands in the
alert's `analysis` field (and as a quote in Slack messages): one to
three sentences on the likely cause and what to check first. Detection
doesn't depend on it. If the API is slow, down, or over
`max_per_hour`, the alert goes out without an analysis. It uses the
official Go SDK, `claude-opus-5-5` at low effort by default, and needs
`ANTHROPIC_API_KEY`.

## How it's built

- `internal/dockerclient`: a minimal Docker Engine API client over a
  unix socket (no docker SDK dependency), compatible with both Docker
  and Podman.
- `internal/detector`: the `Detector` (poll snapshots), `EventDetector`
  (event stream) and `HostDetector` interfaces, and the detectors above.
- `internal/probe`: the HTTP/TCP/TLS prober and the certificate expiry
  detector.
- `internal/engine`: runs the poll loop (host checks, container
  snapshots, expected containers), the event loop and the probe loop
  side by side. Tracks open episodes, applies the cooldown and silences,
  fetches the last 20 log lines for new alerts, redacts, and hands
  alerts to a dispatcher goroutine that runs the LLM layer and the
  actions, so neither can stall detection. A broken connection to the
  Docker socket doesn't crash the daemon: both loops retry with
  exponential backoff (1s → 30s), and the event stream resumes from the
  last event it saw, so nothing that happened during the outage is lost.
- `internal/action`: the `Action` interface and the alert `Record`
  schema. `ConsoleAction` prints each alert as a JSON line to stdout
  (always on). `HTTPAction` is the queued, retrying sender behind the
  webhook, Telegram and ntfy receivers; `Routed` puts a route in front
  of each.
- `internal/silence`: silences and deploy windows.
- `internal/server`: `/metrics`, `/healthz`, the control API and its
  client.
- `internal/redact`, `internal/heartbeat`, `internal/llm`: the pieces
  described above.
- `internal/dockertest`: a fake Docker API on a unix socket, used by the
  client and engine tests.

## Running

### Binary + systemd

Grab a binary from the releases page (or `go build ./cmd/nodux`), then:

```sh
install -m 755 nodux /usr/local/bin/nodux
install -d /etc/nodux && install -m 644 config.example.yaml /etc/nodux/config.yaml
install -m 600 /dev/null /etc/nodux/env     # NODUX_SLACK_PATH=..., ANTHROPIC_API_KEY=...
install -m 644 deploy/nodux.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now nodux
journalctl -u nodux -f
```

The unit runs as a dynamic user in the `docker` group with the usual
systemd sandboxing. The control socket goes in `/run/nodux`, which the
unit creates (`RuntimeDirectory=`); `sudo nodux status` reaches it.

### Docker

```sh
docker run -d --name nodux --restart=always \
  --hostname "$(hostname)" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -v /etc/nodux/config.yaml:/etc/nodux/config.yaml:ro \
  --env-file /etc/nodux/env \
  --security-opt label=disable \
  ghcr.io/skipjust12/nodux:latest

docker exec nodux /nodux status
```

With `-v /:/host:ro`, set `host.disk.paths: [/host]`. `/proc/stat`,
`/proc/meminfo`, `/proc/vmstat` and `/proc/pressure` inside the
container already describe the host. For Prometheus, set
`server.listen: 0.0.0.0:9321` and publish it to the host only
(`-p 127.0.0.1:9321:9321`). Probes run from inside nodux's container:
`127.0.0.1` there is the container itself, so probe other containers by
a network they share, or run nodux with `--network host`.

Two things to know before you do this:

- Access to the Docker socket is root on the host. Mounting it `:ro`
  changes nothing, because the API stays fully usable. That's true for
  any tool that reads the socket, nodux included.
- On SELinux hosts (Fedora, RHEL) a container can't connect to the
  Docker socket by default. `--security-opt label=disable` lifts that for
  this one container. Don't use `:z` on the socket, which relabels the
  host's socket file.

### Podman

For rootless Podman on Linux, start the Docker-compatible API:

```sh
systemctl --user enable --now podman.socket
# or: podman system service --time=0 unix:///run/user/$(id -u)/podman/podman.sock &
```

and point `docker.socket_path` at `/run/user/$(id -u)/podman/podman.sock`.
The event and exit-code handling follows Docker's API. The
Podman-specific `containerExitCode` attribute is accepted as a fallback,
but this path hasn't been exercised against a live Podman yet.

### From source

```sh
cp config.example.yaml config.yaml
go run ./cmd/nodux --config config.yaml
```

## Testing against real containers

Each of these should produce exactly the alerts listed (stdout, one
JSON line each):

```sh
# exit, then crashloop after a few restarts
docker run -d --name crasher --restart=always busybox sh -c 'echo boom; exit 1'

# oom (one alert, even though it keeps restarting), then crashloop
docker run -d --name hog --restart=always -m 16m --memory-swap 16m \
  busybox sh -c 'sleep 2; x=a; while true; do x="$x$x"; done'

# memory (after for_seconds)
docker run -d --name fat -m 64m --memory-swap 64m \
  busybox sh -c 'dd if=/dev/zero of=/dev/shm/f bs=1M count=58; sleep 1000'

# cpu_throttle (after for_seconds)
docker run -d --name busy --cpus 0.2 busybox sh -c 'while :; do :; done'

# unhealthy, the moment the healthcheck flips (held back by the deploy
# window for deploy_grace_seconds, since the container was just created);
# `docker exec sick touch /tmp/ok` resolves it
docker run -d --name sick --health-cmd 'cat /tmp/ok || (echo 503; false)' \
  --health-interval 2s --health-retries 2 busybox sleep 1000

# host_oom: a non-Docker cgroup hitting its limit (cgroup v1 shown; on
# v2 use systemd-run --scope -p MemoryMax=16M python3 ...)
mkdir /sys/fs/cgroup/memory/notdocker
echo 16M > /sys/fs/cgroup/memory/notdocker/memory.limit_in_bytes
sh -c 'echo $$ > /sys/fs/cgroup/memory/notdocker/cgroup.procs;
  exec python3 -c "x=[]
while True: x.append(bytearray(1<<20))"' 

# nothing: a manual stop, even one that escalates to SIGKILL (exit 137)
docker run -d --name calm busybox sleep 1000 && docker stop -t 1 calm

# nothing for the reload; exit for the crash after it
docker run -d --name web nginx:alpine && docker kill -s HUP web
kill -9 "$(docker inspect -f '{{.State.Pid}}' web)"
```

Removing a container mid-episode (`docker rm -f crasher fat`) sends
`container removed` resolutions.

Example alert and resolution:

```json
{"timestamp":"2026-09-28T19:12:23Z","state":"firing","host":"vps1","detector":"crashloop","severity":"critical","message":"container restarted 3 times in the last 5m0s after crashing","container_id":"...","container_name":"crasher","status":"running","restart_count":3,"last_exit_code":1,"logs":["boom","boom","boom"]}
{"timestamp":"2026-09-28T19:13:05Z","state":"resolved","host":"vps1","detector":"unhealthy","severity":"warning","message":"resolved after 37s (was: healthcheck failing (2 consecutive failures): 503)","container_id":"...","container_name":"sick","status":"running","restart_count":0,"last_exit_code":0,"health_status":"healthy"}
```

Host-level alerts have `resource` (a mount point, `memory`, `cpu`,
`daemon`) instead of the container fields.

Clean up:

```sh
docker rm -f crasher hog fat busy sick calm web
rmdir /sys/fs/cgroup/memory/notdocker
```

## Tests

```sh
go test -race ./...
```

CI runs gofmt, `go vet`, the race-enabled tests and a Docker build on
every push and PR. Pushing a `v*` tag publishes static linux/amd64 and
linux/arm64 binaries as a GitHub release and a multi-arch image to
`ghcr.io/<owner>/nodux`.
