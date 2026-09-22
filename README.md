# nodux

A lightweight self-hosted daemon for VPS boxes running Docker/Podman:
detects common container problems with pure deterministic logic (no
LLM) — `docker inspect` / exit codes / restart count. Currently ships
one detector, **crashloop**; the architecture is built so more
detectors and actions can be added.

## How it's built

- `internal/dockerclient` — a minimal Docker Engine API client over a
  unix socket (no docker SDK dependency), compatible with both Docker
  and Podman.
- `internal/detector` — the `Detector` interface + `CrashLoopDetector`.
- `internal/action` — the `Action` interface + `ConsoleAction` (prints
  each detected problem as a JSON line to stdout).
- `internal/llm` — a `Classifier`/`NoopClassifier` stub, the extension
  point for a future optional LLM layer that classifies ambiguous
  detector hits. Currently a no-op.
- `internal/engine` — the poll loop: polls containers, runs them
  through the detectors, fetches the last 20 log lines on a hit, and
  dispatches the issue to every action. A broken connection to the
  Docker socket doesn't crash the daemon — polling retries with
  exponential backoff (1s → 30s).

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

## Testing against a real container

Start a container that crashes right after boot:

```sh
docker run -d --name crasher --restart=always busybox sh -c 'echo boom; exit 1'
```

After a few restarts (threshold and window come from
`detectors.crashloop` in the config), the daemon's stdout will print a
JSON line like:

```json
{"timestamp":"2026-09-22T15:40:00Z","detector":"crashloop","severity":"critical","message":"container restarted 3 times in the last 5m0s","container_id":"...","container_name":"crasher","restart_count":3,"last_exit_code":1,"logs":["boom","boom","boom"]}
```

Clean up the test container when done:

```sh
docker rm -f crasher
```

## Tests

```sh
go test ./...
```
