FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /nodux ./cmd/nodux

# distroless/static has CA certificates (for webhooks) and nothing else.
# It runs as root: talking to the Docker socket needs root or the docker
# group anyway, and either one is root-equivalent on the host.
FROM gcr.io/distroless/static-debian12
COPY --from=build /nodux /nodux
ENTRYPOINT ["/nodux"]
CMD ["--config", "/etc/nodux/config.yaml"]
