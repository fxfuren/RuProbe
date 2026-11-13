# syntax=docker/dockerfile:1.7
# Multi-stage: сборка в отдельном образе, рантайм — минимальный.
# CGO не нужен: все зонды на чистом Go, включая ICMP (raw-сокет требует
# CAP_NET_RAW в рантайме, но не сборки с cgo).

FROM golang:1.27.4-alpine AS build

WORKDIR /src

# Слой зависимостей отдельно от кода: пересборка при правке .go не тянет модули.
COPY go.mod ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

# GOTOOLCHAIN=local: образ уже содержит нужный тулчейн, автозагрузка не нужна
# и в сборке без сети была бы ошибкой.
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/agent ./cmd/agent \
    && go vet ./...

FROM alpine:3.22

# wget из busybox используется healthcheck'ом, сертификаты — для TLS-проб.
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 ruprobe

COPY --from=build /out/agent /usr/local/bin/agent

USER ruprobe
EXPOSE 8080

# Healthcheck на /health, а не на TCP-порт: сервер может слушать, но не быть готов.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/agent"]
