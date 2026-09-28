# nodux

A lightweight self-hosted AIOps daemon for VPS boxes running
Docker/Podman: it detects common container and host problems with plain
deterministic logic (`docker inspect`, the daemon's event stream, exit
codes, healthchecks, `/proc`, `statfs`) and sends alerts to stdout and
a webhook (Slack, Mattermost, Discord, anything that takes JSON). An
optional LLM layer adds a short probable-cause note to container alerts.

## Detectors

| Detector      | Source         | Severity | Fires when |
|---------------|----------------|----------|------------|
| `crashloop`   | events + poll  | critical | a container was restarted after a crash `restart_threshold` times within `window_minutes` |
| `unhealthy`   | poll           | warning  | a running container's `HEALTHCHECK` reports `unhealthy` (includes the last check's output) |
| `oom`         | events         | critical | the kernel OOM killer hit the container's memory limit |
| `exit`        | events         | warning  | the main process exited with a non-zero code on its own (crash, segfault, external `kill -9`) |
| `memory`      | poll           | warning  | memory usage stays ≥ `threshold_percent` of the container's limit for `for_seconds`: the early warning before `oom` |
| `expected`    | poll           | critical | a container listed in `detectors.expected.containers` doesn't exist or isn't running |
| `host_disk`   | host           | critical | a filesystem is ≥ `threshold_percent` full, by space or inodes |
| `host_memory` | host           | warning  | host memory in use (MemTotal − MemAvailable) stays ≥ threshold for `for_seconds` |
| `host_cpu`    | host           | warning  | host CPU busy time stays ≥ threshold for `for_seconds` |
| `docker`      | poll           | critical | the Docker daemon has been unreachable for `down_alert_after_seconds` |

Everything is on by default; an empty config file is a valid config.

### Alerts and resolutions

`oom` and `exit` report one-off events. The same detector won't alert
twice on the same container name within `alert_cooldown_minutes`
(default 10), so a crash-looping container gives you one `exit` alert,
not one per restart.

Everything else tracks a state that starts and ends. You get one alert
when the problem starts and one `"state": "resolved"` message when it
ends, for example `resolved after 12m (was: healthcheck failing …)`,
or `container removed after 3m` if the container is deleted in the
meantime. Threshold detectors (`memory`, `host_*`) only resolve once the
value drops 5 points below the threshold, so something hovering at the
line doesn't flap.

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

`memory` measures usage the way `docker stats` does (minus reclaimable
page cache), only for containers started with a memory limit. Without
one, the "limit" is the host's RAM, which is what `host_memory` checks.

`unhealthy` ignores stopped containers: Docker marks a container with a
healthcheck `unhealthy` when it stops, even on a plain `docker stop`.

## What leaves the host

- **Redaction.** Before an alert goes to a webhook or the LLM, its
  message and log lines are scrubbed: `password=…`, `token: …`, bearer
  tokens, `user:pass@` in URLs, AWS/GitHub/Slack/`sk-…` keys. Add your
  own patterns under `redact.patterns`. Log lines are also cut at 1000
  bytes.
- **Secrets in config.** Webhook URLs, headers, the heartbeat URL and the
  LLM key can reference environment variables (`${NODUX_SLACK_PATH}`).
  An unset or empty variable is a startup error rather than a silently
  broken URL. Webhook and heartbeat URLs never appear in nodux's own
  logs (only scheme and host), because for Slack or Discord the URL is
  the credential.
- **Hostname.** Every alert carries `host`, so alerts from several
  servers in one channel can be told apart.

## Watching nodux itself

- `docker` alerts when the daemon stops answering, and resolves when it
  comes back. Host checks keep running in the meantime.
- `heartbeat` pings a dead man's switch (healthchecks.io, an Uptime Kuma
  push monitor, …) every `interval_seconds` while nodux can reach the
  daemon. If nodux dies or loses Docker, the pings stop and that service
  alerts you from outside the box.

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
- `internal/engine`: runs the poll loop (host checks, container
  snapshots, expected containers) and the event loop side by side.
  Tracks open episodes, applies the cooldown, fetches the last 20 log
  lines for new alerts, redacts, and hands alerts to a dispatcher
  goroutine that runs the LLM layer and the actions, so neither can
  stall detection. A broken connection to the Docker socket doesn't
  crash the daemon: both loops retry with exponential backoff
  (1s → 30s), and the event stream resumes from the last event it saw,
  so nothing that happened during the outage is lost.
- `internal/action`: the `Action` interface and the alert `Record`
  schema. `ConsoleAction` prints each alert as a JSON line to stdout
  (always on). `WebhookAction` POSTs it to a URL, either as the same
  JSON record or Slack-style `{"text": ...}` kept under Discord's 2000
  character limit. Webhook delivery runs on a background queue, retries
  network errors, 5xx and 429 (3 attempts), not other 4xx, and drains
  pending alerts on shutdown.
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
systemd sandboxing.

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
```

With `-v /:/host:ro`, set `host.disk.paths: [/host]`. `/proc/stat` and
`/proc/meminfo` inside the container already describe the host.

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

# unhealthy; `docker exec sick touch /tmp/ok` resolves it
docker run -d --name sick --health-cmd 'cat /tmp/ok || (echo 503; false)' \
  --health-interval 2s --health-retries 2 busybox sleep 1000

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
docker rm -f crasher hog fat sick calm web
```

## Tests

```sh
go test -race ./...
```

CI runs gofmt, `go vet`, the race-enabled tests and a Docker build on
every push and PR. Pushing a `v*` tag publishes static linux/amd64 and
linux/arm64 binaries as a GitHub release and a multi-arch image to
`ghcr.io/<owner>/nodux`.
