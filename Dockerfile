# syntax=docker/dockerfile:1

FROM golang:bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && corepack enable \
    && cd ui && pnpm install --frozen-lockfile && pnpm run build \
    && cd .. \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -tags webui -o /out/arx-dns ./cmd/arx-dns/ \
    && apt-get purge -y curl nodejs && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /runtime/etc/arx-dns/zones /runtime/etc/arx-dns/blocklists

FROM scratch

COPY --from=builder /out/arx-dns /arx-dns
COPY --from=builder /runtime/etc/arx-dns /etc/arx-dns

EXPOSE 53/udp
EXPOSE 53/tcp

ENTRYPOINT ["/arx-dns", "-config", "/etc/arx-dns/config.toml"]
