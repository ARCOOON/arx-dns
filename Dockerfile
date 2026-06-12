# syntax=docker/dockerfile:1

FROM golang:bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/arx-dns ./cmd/arx-dns/

RUN mkdir -p /runtime/etc/arx-dns/zones /runtime/etc/arx-dns/blocklists

FROM scratch

COPY --from=builder /out/arx-dns /arx-dns
COPY --from=builder /runtime/etc/arx-dns /etc/arx-dns

EXPOSE 53/udp
EXPOSE 53/tcp

ENTRYPOINT ["/arx-dns", "-config", "/etc/arx-dns/config.toml"]
