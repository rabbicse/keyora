# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.26-alpine AS build
WORKDIR /src
# The server binary is its own module (it carries the database drivers);
# it builds against the core module in the repository root.
COPY go.mod ./
COPY cmd/keyora/go.mod cmd/keyora/go.sum ./cmd/keyora/
RUN cd cmd/keyora && go mod download
COPY . .
ARG VERSION=dev
RUN cd cmd/keyora && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/keyora . \
 && mkdir -p /out/data

# ---- runtime ----
# Distroless static: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keyora /usr/local/bin/keyora
COPY --from=build --chown=nonroot:nonroot /out/data /data

ENV KEYORA_HTTP_ADDR=:8080 \
    KEYORA_DB_DRIVER=sqlite \
    KEYORA_DB_DSN=file:/data/keyora.db \
    KEYORA_KEYS_DIR=/data/keys

VOLUME /data
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/keyora", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/keyora"]
CMD ["serve"]
