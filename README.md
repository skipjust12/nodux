# nodux

A lightweight self-hosted AIOps daemon for VPS boxes running
Docker/Podman: it detects common container and host problems with plain
deterministic logic (`docker inspect`, the daemon's event stream, exit
codes, healthchecks, `/proc`, `statfs`) and sends alerts to stdout and
a webhook (Slack, Mattermost, Discord, anything that takes JSON).
Related alerts are grouped into incidents, and nodux remembers what's
open across restarts and keeps a history of what happened.

An optional LLM layer investigates each incident with read-only tools
and adds a short probable-cause note, answers questions in a Telegram
chat ("what's wrong with api?"), and writes the takeaway of a daily or
weekly digest.

## Detectors

| Detector      | Source         | Severity | Fires when |
|---------------|----------------|----------|------------|
| `crashloop`   | events + poll  | critical | a container was restarted after a crash `restart_threshold` times within `window_minutes` |
| `unhealthy`   | poll           | warning  | a running container's `HEALTHCHECK` reports `unhealthy` (includes the last check's output) |
| `oom`         | events         | critical | the kernel OOM killer hit the container's memory limit |
| `exit`        | events         | warning  | the main process exited with a non-zero code on its own (crash, segfault, external `kill -9`) |
| `memory`      | poll           | warning  | memory usage stays ≥ `threshold_percent` of the container's limit for `for_seconds`: the early warning before `oom` |
| `expected`    | poll           | critical | a container listed in `detectors.expected.containers` (or labeled `nodux.expected=true`) doesn't exist or isn't running |
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

### Incidents

One failure rarely comes alone: host memory runs out, two containers
get OOM-killed, one of them starts crash-looping. nodux groups such
alerts into an incident and sends them as one message (with one LLM
analysis) instead of five. Grouping is deterministic. An alert joins a
recent incident (its last alert less than `window_minutes` old) when it
shares something with it:

- the same container;
- the same compose project (the database dies, then the API that needs
  it);
- the host: a host-level alert (disk, memory, CPU, the Docker daemon)
  is a plausible cause of anything failing at the same time, so it
  joins, and pulls in, whatever fails while it's open.

Alerts are held for `group_wait_seconds` (default 30) so a burst arrives
together; later alerts of the same incident go out as updates, and a
resolution goes out with the incident it started in. Every alert record
carries its `incident_id`. `incidents.enabled: false` sends each alert
on its own, right away, as before.

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

## Per-container labels

Containers can say how they want to be watched, which fits compose
files better than a list of names in nodux's config:

```yaml
services:
  api:
    labels:
      nodux.expected: "true"           # must be running
      nodux.memory.threshold: "80"     # % of its memory limit
      nodux.memory.for: "2m"
  migrate:
    labels:
      nodux.exit.ignore: "0,3"         # exit codes that aren't a crash
  scratch:
    labels:
      nodux.enable: "false"            # never checked, invisible to the LLM
```

| Label | Effect |
|-------|--------|
| `nodux.enable=false` | the container is never checked (like `exclude_containers`) |
| `nodux.expected=true` | the container must be running, for as long as it exists |
| `nodux.<detector>.enable=false` | turns off one detector: `crashloop`, `unhealthy`, `oom`, `exit`, `memory` |
| `nodux.memory.threshold`, `nodux.memory.for` | the `memory` detector's threshold (%) and duration |
| `nodux.crashloop.threshold`, `nodux.crashloop.window` | restarts within a window |
| `nodux.exit.ignore` | comma-separated exit codes `exit` doesn't report |

Durations take Go syntax (`90s`, `5m`) or plain seconds. A label with a
value that doesn't parse is ignored, with a warning in the log.

Unlike `detectors.expected.containers`, a labeled container is only
expected while it exists: `compose down` removes the container and the
label with it. List a name in the config when its absence is a problem.

## Surviving restarts

With `state_dir` (default `/var/lib/nodux`), nodux keeps two files:

- `state.json`: open alerts, detector state (half-counted crash loops,
  thresholds that are firing, grace periods in progress), cooldowns,
  and the position in Docker's event stream. It's rewritten atomically
  (temp file, fsync, rename) after each poll, only when it changed.
- `history.db`: SQLite (pure Go, no cgo) with every alert sent, the LLM
  layer's token usage, and each running container's memory every five
  minutes. Alerts are kept for `history.retention_days` (default 30),
  memory samples for two weeks.

After a restart or an upgrade, what's still broken isn't alerted again;
what got fixed while nodux was down is resolved (`resolved after 2h`,
or `container removed after 2h`); and the event stream resumes where it
stopped, so a crash during the restart isn't lost. The daemon only
buffers recent events, and nodux replays at most the last hour. A
corrupt or incompatible state file is logged and ignored.

`state_dir: ""` keeps everything in memory, like before, and turns the
digest off.

## What leaves the host

- **Redaction.** Before anything goes to a webhook, the LLM or the chat,
  messages, log lines and the output of the LLM's tools are scrubbed:
  `password=…`, `token: …`, `--token …`, bearer tokens, `user:pass@` in
  URLs, AWS/GitHub/Slack/`sk-…` keys. Add your own patterns under
  `redact.patterns`. Log lines are also cut at 1000 bytes. The LLM sees
  the names of a container's environment variables, never their values.
- **Secrets in config.** Webhook URLs, headers, the heartbeat URL, the
  LLM key and the Telegram token can reference environment variables
  (`${NODUX_SLACK_PATH}`). An unset or empty variable is a startup
  error rather than a silently broken URL. Webhook, heartbeat and
  Telegram URLs never appear in nodux's own logs (only scheme and host),
  because for Slack or Discord the URL is the credential.
- **Hostname.** Every alert carries `host`, so alerts from several
  servers in one channel can be told apart.
- **The state files** are 0600 (and the directory 0700 when nodux
  creates it): alert messages stay on the host.

## Watching nodux itself

- `docker` alerts when the daemon stops answering, and resolves when it
  comes back. Host checks keep running in the meantime.
- `heartbeat` pings a dead man's switch (healthchecks.io, an Uptime
  Kuma push monitor, …) every `interval_seconds` while nodux can reach
  the daemon. If nodux dies or loses Docker, the pings stop and that
  service alerts you from outside the box.

## LLM layer (optional)

With `llm.enabled: true`, each incident is sent to Claude before it goes
out, and the reply lands in the alerts' `analysis` field (and as a
quote in Slack messages): one to three sentences on the likely cause
and what to check first. Detection doesn't depend on it: if the API is
slow, down, or over `max_per_hour`, the alert goes out without an
analysis.

The model gets more than the alert and its logs:

- how long the container ran before it died ("100ms after start" is a
  config problem, "after 3 days" a leak),
- its image, and whether nodux saw it change recently (a deploy),
- when the container was created, its restart policy and memory limit
  and use,
- its earlier alerts from the history.

And it can look further, with up to `max_steps` (default 4) rounds of
read-only tools:

| Tool | What it returns |
|------|-----------------|
| `list_containers` | name, image, state and status, compose project |
| `inspect_container` | image, created/started/exited, restarts, exit code, OOM flag, recent healthchecks, limits, command, names of env variables, mounts |
| `container_logs` | log lines with timestamps, in a time range around the failure, or only lines containing a string |
| `container_stats` | CPU over a second, memory against its limit, CPU throttling, I/O, processes |
| `docker_disk_usage` | `docker system df`: images (and how much no container uses), writable layers, volumes, build cache |
| `host_overview` | uptime, load, memory and swap, filesystems, pressure stall info, the processes using the most memory and CPU |
| `alert_history` | what's open now and past alerts, for one container or everything |

None of them can change anything: they're GET requests to the Docker
API and reads of `/proc`. Containers nodux ignores are invisible to
them. Host alerts get analyzed too: a full disk comes back with what in
Docker is taking the space.

It uses the official Go SDK, `claude-opus-5-5` at `effort: low` by
default, with prompt caching and server-side refusal fallbacks, and
needs `ANTHROPIC_API_KEY`. `max_per_hour` caps analyses, chat answers
and digest notes together. Token usage goes to the history, and the
digest reports it with a cost estimate at list prices.

## Digest

With `digest.enabled: true` (needs `state_dir`), a report goes out
through the same actions every day or week at `digest.at`, local time:

```
*nodux daily digest* for vps1, Sep 30 09:00 – Oct 1 09:00 CEST
*Alerts:* 14 (5 critical) in 3 incidents, 9 resolutions
*Containers:*
• `api`: exit ×5, oom ×2, crashloop ×1
• `worker`: unhealthy ×3
*Host:* `/`: host_disk ×1
*Flapping:* unhealthy `worker` opened 3 times
*Still open:* crashloop `api` (2h), host_disk `/` (3d)
*Memory growing:* `api` 210.0MiB → 340.0MiB (+62%) of 512.0MiB limit
*LLM:* 6 analyses in 18 requests, 210k input tokens (180k from cache), 9k output, about $0.31
> api has been OOM-killed twice since Tuesday's deploy and its memory keeps climbing: look for a leak in that release first.
```

The last line is the LLM's takeaway, when the layer is on. JSON
consumers get the same report as data (`"kind": "digest"`). To see the
digest without waiting: `nodux --config /etc/nodux/config.yaml -digest`.

## Telegram bot

```yaml
chatops:
  telegram:
    enabled: true
    token: ${NODUX_TELEGRAM_TOKEN}   # from @BotFather
    allowed_chat_ids: [123456789]
```

Ask it anything about the host in plain language, in any language:
"что с api?", "why is the disk full?", "did anything restart tonight?".
The LLM answers with the same read-only tools. `/status` (open alerts
and containers) and `/alerts [container]` (last 24 hours) work without
the LLM layer.

The bot long-polls Telegram, so nothing on the host listens for
connections. It answers only the chats in `allowed_chat_ids` (in a
group, anyone in it); to find your chat ID, write to the bot and look
in nodux's log. Messages older than ten minutes (sent while nodux was
down) are skipped.

## How it's built

- `internal/dockerclient`: a minimal, read-only Docker Engine API client
  over a unix socket (no docker SDK dependency), compatible with both
  Docker and Podman.
- `internal/detector`: the `Detector` (poll snapshots), `EventDetector`
  (event stream) and `HostDetector` interfaces, the detectors above,
  and the container labels.
- `internal/engine`: runs the poll loop (host checks, container
  snapshots, expected containers) and the event loop side by side.
  Tracks open episodes, applies the cooldown, fetches the last 20 log
  lines for new alerts, redacts, and hands alerts to a dispatcher that
  groups them into incidents, runs the LLM layer and the actions, and
  records the history, so none of that can stall detection. A broken
  connection to the Docker socket doesn't crash the daemon: both loops
  retry with exponential backoff (1s → 30s), and the event stream
  resumes from the last event it saw. Saves and restores the state.
- `internal/incident`: the grouping.
- `internal/state`, `internal/history`: `state.json` and `history.db`.
- `internal/llm`: the Claude client and its tool-use loop;
  `internal/tools`: the read-only tools.
- `internal/action`: the `Action` interface and the alert `Record`
  schema. `ConsoleAction` prints each alert as a JSON line to stdout
  (always on). `WebhookAction` POSTs to a URL, either each alert as the
  same JSON record, or one Slack-style `{"text": ...}` message per
  incident, kept under Discord's 2000 character limit. Webhook delivery
  runs on a background queue, retries network errors, 5xx and 429 (3
  attempts), not other 4xx, and drains pending alerts on shutdown.
- `internal/digest`, `internal/chatops`, `internal/redact`,
  `internal/heartbeat`: the pieces described above.
- `internal/dockertest`: a fake Docker API on a unix socket, used by the
  client, engine and tools tests.

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
systemd sandboxing; `StateDirectory=nodux` gives it `/var/lib/nodux`.
Upgrading from a version without `state_dir`: install the new unit
too, or nodux can't create its state directory and won't start.

### Docker

```sh
docker run -d --name nodux --restart=always \
  --hostname "$(hostname)" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -v nodux-state:/var/lib/nodux \
  -v /etc/nodux/config.yaml:/etc/nodux/config.yaml:ro \
  --env-file /etc/nodux/env \
  -e TZ=Europe/Berlin \
  --security-opt label=disable \
  ghcr.io/skipjust12/nodux:latest
```

With `-v /:/host:ro`, set `host.disk.paths: [/host]`. `/proc/stat` and
`/proc/meminfo` inside the container already describe the host. The
`nodux-state` volume keeps open alerts and the history across
container recreation. `TZ` sets the digest's time zone. Add
`--pid=host` if the LLM's `host_overview` should see the host's
processes, not just nodux's own.

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
and when events don't carry container labels, the labels from the last
poll apply. This path hasn't been exercised against a live Podman yet.

### From source

```sh
cp config.example.yaml config.yaml   # set state_dir to a directory you can write
go run ./cmd/nodux --config config.yaml
```

## Testing against real containers

Each of these should produce exactly the alerts listed (stdout, one
JSON line each; with incidents on, they arrive `group_wait_seconds`
later and share an `incident_id` where related):

```sh
# exit, then crashloop after a few restarts: one incident
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

# labels: nothing for vault; expected for api after its grace period;
# memory for thin (about 64% of its limit, over its own 50%)
docker run -d --name vault --label nodux.enable=false --restart=always busybox sh -c 'exit 3'
docker run -d --name api --label nodux.expected=true busybox true
docker run -d --name thin -m 64m --memory-swap 64m --label nodux.memory.threshold=50 \
  --label nodux.memory.for=0 busybox sh -c 'dd if=/dev/zero of=/dev/shm/f bs=1M count=40; sleep 1000'
```

Removing a container mid-episode (`docker rm -f crasher fat`) sends
`container removed` resolutions. Stopping nodux, running `docker exec
sick touch /tmp/ok` and starting it again sends `resolved after …` for
`sick` and nothing new for what's still broken.

Example alert and resolution:

```json
{"kind":"alert","timestamp":"2026-09-28T19:12:23Z","state":"firing","host":"vps1","detector":"crashloop","severity":"critical","message":"container restarted 3 times in the last 5m0s after crashing","incident_id":12,"container_id":"...","container_name":"crasher","image":"busybox","status":"running","restart_count":3,"last_exit_code":1,"logs":["boom","boom","boom"]}
{"kind":"alert","timestamp":"2026-09-28T19:13:05Z","state":"resolved","host":"vps1","detector":"unhealthy","severity":"warning","message":"resolved after 37s (was: healthcheck failing (2 consecutive failures): 503)","incident_id":13,"container_id":"...","container_name":"sick","image":"busybox","status":"running","restart_count":0,"last_exit_code":0,"health_status":"healthy"}
```

Host-level alerts have `resource` (a mount point, `memory`, `cpu`,
`daemon`) instead of the container fields.

Clean up:

```sh
docker rm -f crasher hog fat sick calm web vault api thin
```

## Tests

```sh
go test -race ./...
```

CI runs gofmt, `go vet`, the race-enabled tests and a Docker build on
every push and PR. Pushing a `v*` tag publishes static linux/amd64 and
linux/arm64 binaries as a GitHub release and a multi-arch image to
`ghcr.io/<owner>/nodux`.
