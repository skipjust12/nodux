# nodux

A lightweight self-hosted AIOps daemon for VPS boxes running
Docker/Podman: detects common container problems with pure
deterministic logic (no LLM yet) — `docker inspect`, the daemon's event
stream, exit codes, restart counts, healthchecks. An optional LLM layer
for triaging ambiguous hits is stubbed out for later.

## Detectors

| Detector    | Source | Severity | Fires when |
|-------------|--------|----------|------------|
| `crashloop` | poll   | critical | a container restarted `restart_threshold` times within `window_minutes` |
| `unhealthy` | poll   | warning  | the container's `HEALTHCHECK` reports `unhealthy` (once per episode; includes the last check's output) |
| `oom`       | events | critical | the kernel OOM killer hit the container's memory limit |
| `exit`      | events | warning  | the main process exited with a non-zero code on its own (crash, segfault, external `kill -9`) |

Why two sources: some failures are gone by the next poll. With a
restart policy, Docker clears `State.OOMKilled` on the very next start,
so an OOM in a restarting container is effectively invisible to
polling — it's only reliable as an `oom` event. The same stream tells
crashes apart from intentional stops: `docker stop` / `kill` /
`restart` / `rm -f` / `compose down` all emit `kill` events before
`die`, a crash is a bare `die`, so `exit` never fires on manual stops.

Every alert goes through a cooldown (`alert_cooldown_minutes`, default
10): the same detector won't re-alert on the same container name within
that window, so a crash-looping container gives you one `exit` and one
`crashloop` alert, not one per restart.

## How it's built

- `internal/dockerclient` — a minimal Docker Engine API client over a
  unix socket (no docker SDK dependency), compatible with both Docker
  and Podman.
- `internal/detector` — the `Detector` (poll snapshots) and
  `EventDetector` (event stream) interfaces and the detectors above.
- `internal/action` — the `Action` interface + `ConsoleAction` (prints
  each detected problem as a JSON line to stdout).
- `internal/llm` — a `Classifier`/`NoopClassifier` stub, the extension
  point for a future optional LLM layer that classifies ambiguous
  detector hits. Currently a no-op.
- `internal/engine` — runs two loops side by side: the poll loop feeds
  container snapshots to `Detector`s, the event loop follows `/events`
  and feeds `EventDetector`s. On a hit it fills in state from inspect,
  fetches the last 20 log lines, applies the cooldown, and dispatches
  the issue to every action. A broken connection to the Docker socket
  doesn't crash the daemon — both loops retry with exponential backoff
  (1s → 30s), and the event stream resumes from the last event it saw,
  so nothing that happened during the outage is lost.
- `internal/dockertest` — a fake Docker API on a unix socket, used by
  the client and engine tests.

## Running locally

```sh
cp config.example.yaml config.yaml
# adjust socket_path for Docker Desktop/Podman if needed

go run ./cmd/nodux --config config.yaml
```

For Podman (rootless, Linux), start the Docker-compatible API first:

```sh
podman system service --time=0 unix:///run/user/$(id -u)/podman/podman.sock &
```

and point `docker.socket_path` at that socket.

## Testing against real containers

Each of these should produce exactly the alerts listed (stdout, one
JSON line each):

```sh
# exit, then crashloop after a few restarts
docker run -d --name crasher --restart=always busybox sh -c 'echo boom; exit 1'

# oom (one alert, even though it keeps restarting)
docker run -d --name hog --restart=always -m 16m --memory-swap 16m \
  busybox sh -c 'sleep 2; x=a; while true; do x="$x$x"; done'

# unhealthy
docker run -d --name sick --health-cmd 'echo 503; false' \
  --health-interval 2s --health-retries 2 busybox sleep 1000

# nothing: a manual stop, even one that escalates to SIGKILL (exit 137)
docker run -d --name calm busybox sleep 1000 && docker stop -t 1 calm
```

Example alert:

```json
{"timestamp":"2026-09-24T15:08:50Z","detector":"crashloop","severity":"critical","message":"container restarted 3 times in the last 5m0s","container_id":"...","container_name":"crasher","status":"restarting","restart_count":7,"last_exit_code":1,"logs":["boom","boom","boom"]}
```

Clean up:

```sh
docker rm -f crasher hog sick calm
```

Podman: the event and exit-code handling follows Docker's API; the
Podman-specific `containerExitCode` attribute is accepted as a
fallback, but this path hasn't been exercised against a live Podman yet.

## Tests

```sh
go test -race ./...
```
