# nodux

Лёгкий self-hosted демон для VPS с Docker/Podman: детектит типовые
проблемы у контейнеров чистой детерминированной логикой (без LLM) —
`docker inspect` / exit codes / restart count. Сейчас реализован
детектор **crashloop**; архитектура рассчитана на то, что детекторов и
действий станет больше.

## Как это устроено

- `internal/dockerclient` — свой минимальный клиент Docker Engine API
  поверх unix-сокета (без docker SDK), совместим и с Docker, и с Podman.
- `internal/detector` — интерфейс `Detector` + `CrashLoopDetector`.
- `internal/action` — интерфейс `Action` + `ConsoleAction` (печать
  найденной проблемы JSON-строкой в stdout).
- `internal/llm` — заглушка `Classifier`/`NoopClassifier`, точка
  расширения под будущий опциональный LLM-слой для классификации
  неоднозначных срабатываний. Сейчас ничего не делает.
- `internal/engine` — poll-loop: опрашивает контейнеры, гоняет их через
  детекторы, при срабатывании подтягивает последние 20 строк логов и
  раздаёт issue по действиям. Обрыв связи с Docker сокетом не роняет
  демон — опрос ретраится с экспоненциальным backoff (1s → 30s).

## Запуск локально

```sh
cp config.example.yaml config.yaml
# при необходимости поправьте socket_path под Docker Desktop/Podman

go run ./cmd/nodux --config config.yaml
```

Для Podman (rootless, Linux) сначала поднимите Docker-совместимый API:

```sh
podman system service --time=0 unix:///run/user/$(id -u)/podman/podman.sock &
```

и укажите этот путь в `docker.socket_path`.

## Проверка на тестовом контейнере

Запустите контейнер, который падает почти сразу после старта:

```sh
docker run -d --name crasher --restart=always busybox sh -c 'echo boom; exit 1'
```

Через несколько перезапусков (порог и окно берутся из
`detectors.crashloop` в конфиге) в stdout демона появится JSON-строка вида:

```json
{"timestamp":"2026-09-22T15:40:00Z","detector":"crashloop","severity":"critical","message":"container restarted 3 times in the last 5m0s","container_id":"...","container_name":"crasher","restart_count":3,"last_exit_code":1,"logs":["boom","boom","boom"]}
```

Уберите тестовый контейнер по завершении:

```sh
docker rm -f crasher
```

## Тесты

```sh
go test ./...
```
