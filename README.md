# arx-dns

High-performance, enterprise-grade DNS server for the ARX ecosystem.

## Capabilities

- Authoritative and recursive DNS resolution.
- Native UDP/TCP handling on Port 53 with multi-core scaling.
- In-memory caching, split-horizon routing, and advanced threat mitigation (Response Rate Limiting, RPZ).
- Modern transport support (DoT, DoH, DoQ).

## Architecture

Strictly adheres to KISS and DRY principles. Uses `github.com/panjf2000/gnet/v2` for event-driven reactor I/O (`epoll`/`kqueue`) while keeping full control over the socket lifecycle. DNS wire-format parsing and serialization use `github.com/miekg/dns` as a codec only — routing and I/O remain in `internal/network/`. Authoritative records are served from a thread-safe in-memory radix tree (`internal/storage`).

### Project Layout

| Path                  | Purpose                                                                                                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/arx-dns/`        | Server entrypoint (`-config` flag, signal handling, reactor startup)                                                                                                            |
| `internal/config/`    | Unified TOML configuration loading, validation, and default generation                                                                                                          |
| `internal/network/`   | gnet UDP/TCP reactors with `SO_REUSEPORT`, dual-stack bind, DoT/DoH encrypted listeners, and source-IP ACL matching                                                             |
| `internal/dnsproc/`   | DNS message parse/serialize, authoritative response builder, split-DNS view resolution, CNAME chain resolution, ACL enforcement, firewall interception, and upstream forwarding |
| `internal/firewall/`  | Reversed-domain radix blocklist engine, flat-file loader, and fsnotify hot-reload                                                                                               |
| `internal/storage/`   | Thread-safe dual-view in-memory radix-tree zone store, BIND zone loader, fsnotify hot-reload, and TTL-aware upstream response cache                                             |
| `internal/telemetry/` | Lock-free atomic counters (`sync/atomic`) for operations stats                                                                                                                  |
| `internal/api/`       | Management HTTP API for health checks, telemetry exposure, and zone reload                                                                                                      |

## Build & Run

```bash
go build -o arx-dns ./cmd/arx-dns/
./arx-dns   # reads ./config.toml (auto-created with defaults on first run)
```

## Docker Deployment

Production images use a multi-stage build (`CGO_ENABLED=0`, statically linked binary) and a `scratch` runtime stage for minimal memory footprint. Configuration, zones, and blocklists are mounted from the host at runtime.

### Prerequisites

- Docker Engine with Compose v2
- Host port 53 available (stop conflicting DNS listeners before starting)

### Quick Start

```bash
docker compose up -d --build
dig @127.0.0.1 router.arx.local A
```

### Volume Layout

| Host path            | Container path             | Purpose                                     |
| -------------------- | -------------------------- | ------------------------------------------- |
| `./data/config.toml` | `/etc/arx-dns/config.toml` | TOML runtime configuration                  |
| `./data/zones/`      | `/etc/arx-dns/zones/`      | BIND `.zone` files                          |
| `./data/blocklists/` | `/etc/arx-dns/blocklists/` | Plain-text domain blocklists                |
| `./data/certs/`      | `/etc/arx-dns/certs/`      | TLS certificate and private key for DoT/DoH |

The sample `data/config.toml` uses container paths (`/etc/arx-dns/zones`, `/etc/arx-dns/blocklists`). Edit zone and blocklist files on the host; `fsnotify` hot-reload picks up changes without restarting the container.

### Compose Service

| Setting        | Value                                                                      |
| -------------- | -------------------------------------------------------------------------- |
| Ports          | `53/udp`, `53/tcp`, `853/tcp` (DoT), `443/tcp` (DoH) published to the host |
| Restart policy | `unless-stopped`                                                           |
| Capabilities   | `NET_ADMIN`, `NET_BIND_SERVICE` (port 53, `SO_REUSEPORT`)                  |
| Entrypoint     | `/arx-dns -config /etc/arx-dns/config.toml`                                |

### Multi-Architecture Builds

Build and push images for `linux/amd64` and `linux/arm64` with Docker Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t arx-dns:latest \
  --push .
```

Single-platform local build:

```bash
docker build -t arx-dns:latest .
```

### Configuration

All runtime settings are loaded from a single TOML file. The only CLI flag is `-config` (default: `./config.toml`). When the file does not exist, arx-dns writes a default configuration and continues startup.

| Flag      | Default         | Description                         |
| --------- | --------------- | ----------------------------------- |
| `-config` | `./config.toml` | Path to the TOML configuration file |

Example `config.toml` (generated automatically on first run):

```toml
[server]
listen = '0.0.0.0'
port = 53
event_loops = 0

[zones]
directory = './zones'

[recursive]
upstreams = ['1.1.1.1:53', '1.0.0.1:53']
trusted_subnets = ['127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16']

[firewall]
blocklists_directory = './blocklists'
block_action = 'NXDOMAIN'

[tls]
cert_file = './certs/server.crt'
key_file = './certs/server.key'

[listeners]
dot = ':853'
doh = ':443'

[api]
listen = '127.0.0.1:8080'
auth_token = 'dev-token-change-me'
```

| Section / Key                   | Default                                       | Description                                                                                 |
| ------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `server.listen`                 | `0.0.0.0`                                     | IP address to bind to                                                                       |
| `server.port`                   | `53`                                          | UDP/TCP port to listen on                                                                   |
| `server.event_loops`            | `0`                                           | gnet event loops per protocol (`0` = one per CPU core)                                      |
| `tls.cert_file`                 | _(empty)_                                     | PEM certificate path; required together with `tls.key_file` to enable DoT/DoH               |
| `tls.key_file`                  | _(empty)_                                     | PEM private key path; required together with `tls.cert_file` to enable DoT/DoH              |
| `listeners.dot`                 | `:853`                                        | DNS-over-TLS bind address (`host:port` or `:port`); empty disables DoT                      |
| `listeners.doh`                 | `:443`                                        | DNS-over-HTTPS bind address; empty disables DoH                                             |
| `api.listen`                    | `127.0.0.1:8080`                              | Management API bind address (`host:port`); defaults to localhost for security               |
| `api.auth_token`                | `dev-token-change-me`                         | Bearer token for authenticated API endpoints; change in production                          |
| `zones.directory`               | `./zones`                                     | Directory containing BIND `.zone` files (public view at root; internal view in `internal/`) |
| `recursive.upstreams`           | `1.1.1.1:53`, `1.0.0.1:53`                    | Upstream DNS resolvers for recursive forwarding                                             |
| `recursive.trusted_subnets`     | `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16` | CIDR prefixes allowed to use recursive forwarding                                           |
| `firewall.blocklists_directory` | `./blocklists`                                | Directory containing plain-text domain blocklists (one domain per line)                     |
| `firewall.block_action`         | `NXDOMAIN`                                    | Firewall action for blocked domains: `NXDOMAIN` or `ZEROIP`                                 |

Example:

```bash
./arx-dns -config /etc/arx-dns/config.toml
```

On startup, all `*.zone` files in the zones directory root are loaded into the **public** view. Additional zone files placed in `zones/internal/` are loaded into a separate **internal** view. The zone apex is taken from the filename (e.g. `arx.local.zone` → origin `arx.local.`) or from a `$ORIGIN` directive inside the file. Malformed zone files are logged and skipped; the server continues with the remaining zones.

While the server is running, `fsnotify` watches the zones directory and `zones/internal/` for `Create`, `Write`, and `Remove` events on `.zone` files. Changes are debounced for 500ms (to allow atomic file writes to finish), then all zone files are re-parsed into fresh public and internal radix trees and swapped in atomically via `sync/atomic.Value`. Lookups remain lock-free on the active tree pointers; reload events log the number of loaded zones and any parse errors as structured JSON.

The default `zones/arx.local.zone` ships a small demo zone for immediate testing:

| Name               | Type  | Value              |
| ------------------ | ----- | ------------------ |
| `router.arx.local` | A     | `10.10.0.1`        |
| `router.arx.local` | AAAA  | `fd00::1`          |
| `www.arx.local`    | CNAME | `router.arx.local` |

Valid incoming DNS queries receive an authoritative answer when the name exists, `NXDOMAIN` when the name is unknown and recursion is not requested, or `NOERROR` with an empty answer when the name exists but the requested type is absent.

### EDNS0 (RFC 6891)

When a query includes an OPT pseudo-record in the Additional section, the server echoes EDNS0 support in the response and honors the client's advertised UDP payload size. Values below 512 bytes are treated as 512 per RFC 6891. If the assembled UDP response exceeds the negotiated limit (512 bytes when EDNS0 is absent), the **TC (Truncation)** bit is set and records are omitted until the message fits; clients should retry over TCP. TCP responses are never truncated by UDP size limits but still include an OPT record when the request carried one.

### TCP connection hardening

The TCP reactor enables kernel keep-alive probes (`WithTCPKeepAlive`, 3-minute idle, 30-second interval, 3 probes) to reap dead peers. Each connection must deliver a complete length-prefixed DNS frame within **3 seconds** of opening or since the last completed exchange; otherwise the connection is closed and `tcp_timeouts` is incremented. A 500ms ticker sweeps idle connections that never send data (Slowloris mitigation).

### Split-DNS views

| View       | Directory               | Visibility                                         |
| ---------- | ----------------------- | -------------------------------------------------- |
| `public`   | `zones/*.zone`          | All clients                                        |
| `internal` | `zones/internal/*.zone` | Trusted clients only (`recursive.trusted_subnets`) |

Trusted clients (source IP matches `recursive.trusted_subnets`) query the **internal** view first. On `NXDOMAIN`, the processor falls back to the **public** view. Untrusted clients query only the public view.

### Access control (ACL)

Clients whose source IP does **not** match `recursive.trusted_subnets` may query authoritative public zones only. If such a client sets the **Recursion Desired (RD)** flag for a name outside local zones, the server returns **REFUSED** instead of forwarding upstream. Trusted clients may use recursive forwarding as before.

### DNS firewall (blocklists)

Before cache or authoritative resolution, every query is checked against blocklists loaded from `firewall.blocklists_directory`. Domains are stored in a reversed-label radix tree (`example.com` → `com.example`) so blocking an apex also blocks all subdomains (e.g. `ads.example.com`).

| Key                             | Default        | Behavior                                                                                |
| ------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| `firewall.blocklists_directory` | `./blocklists` | Directory of flat text files; one domain per line; `#` comments and blank lines ignored |
| `firewall.block_action`         | `NXDOMAIN`     | `NXDOMAIN` returns RCODE 3; `ZEROIP` returns `A` → `0.0.0.0` or `AAAA` → `::`           |

Blocklist files are hot-reloaded via `fsnotify` with the same 500ms debounce and atomic tree swap pattern as zone files. Firewall matches take precedence over authoritative zones and the upstream cache.

Example blocklist file (`blocklists/ads.list`):

```text
# Tracking and ad domains
doubleclick.net
ads.example.com
```

Verify blocking:

```bash
dig @127.0.0.1 +short ads.example.com A    # NXDOMAIN (default)
# Set firewall.block_action = "ZEROIP" in config.toml, then:
dig @127.0.0.1 +short ads.example.com A    # 0.0.0.0
```

When a query is not found in the applicable local zone views and the client sets the **Recursion Desired (RD)** flag, the server forwards the query to the configured upstream resolvers (`recursive.upstreams`). Before forwarding, the processor checks an in-memory response cache keyed by question name, type, and class. On a cache hit, record TTLs are decremented by the elapsed time since the response was stored and the cached answer is returned immediately without contacting upstream resolvers. On a cache miss, upstreams are tried sequentially with a 2-second timeout per attempt; the first successful response is stored in the cache using the minimum TTL across Answer and Authority records for eviction, then returned to the client. If every upstream fails or times out, the server returns `SERVFAIL`. All responses set **Recursion Available (RA)** to indicate recursive capability. Hostnames without an explicit port default to `:53`.

For `A` and `AAAA` queries, the processor follows CNAME chains automatically: each alias is appended to the Answer section and the target name is looked up for the originally requested type. Chains are limited to 8 hops with visited-name loop detection; loops or excessive depth return `SERVFAIL`. Direct `CNAME` queries return only the alias record without following the chain. All lookups read the active radix tree via `sync/atomic.Value` without locks.

Verify with:

```bash
dig @127.0.0.1 router.arx.local A
dig @127.0.0.1 www.arx.local A          # CNAME + resolved A in one response
dig @127.0.0.1 www.arx.local CNAME +tcp
dig @127.0.0.1 unknown.example.com A   # NXDOMAIN (no RD flag)
dig @127.0.0.1 +recurse example.com A   # forwarded to upstream resolvers (trusted client)
dig @127.0.0.1 +norecurse secret.internal.zone A   # NXDOMAIN for untrusted clients
```

Graceful shutdown is triggered by `SIGINT` or `SIGTERM`. Final operational counters are logged as JSON on exit.

### Encrypted DNS (DoT & DoH)

When `tls.cert_file` and `tls.key_file` are set, arx-dns starts encrypted DNS listeners in addition to plain UDP/TCP on port 53.

| Transport | Default bind | Protocol                      | Standard |
| --------- | ------------ | ----------------------------- | -------- |
| DoT       | `:853`       | TLS + length-prefixed TCP DNS | RFC 7858 |
| DoH       | `:443`       | HTTPS `GET`/`POST /dns-query` | RFC 8484 |

**DNS-over-TLS:** Clients connect with TLS (ALPN `dot`). Messages use the same 2-byte length prefix + DNS payload framing as TCP port 53. Responses are routed through `dnsproc.Processor.ResponseTCP` (no UDP truncation).

**DNS-over-HTTPS:** The server exposes `/dns-query` only.

- `POST /dns-query` — request body must use `Content-Type: application/dns-message`.
- `GET /dns-query?dns=<base64url>` — wire-format query without padding per RFC 8484.

Responses use `Content-Type: application/dns-message` and `Cache-Control: no-store`.

Generate a development certificate:

```bash
mkdir -p data/certs
openssl req -x509 -newkey rsa:2048 \
  -keyout data/certs/server.key -out data/certs/server.crt \
  -days 3650 -nodes -subj "/CN=arx-dns.local"
```

Verify:

```bash
dig @127.0.0.1 -p 853 +tls router.arx.local A
curl -sk --data-binary @query.bin -H 'Content-Type: application/dns-message' \
  https://127.0.0.1/dns-query -o response.bin
```

Plain UDP/TCP on port 53 continues to work when TLS paths are omitted from `config.toml`.

### Telemetry

`internal/telemetry.Stats` tracks:

| Field                   | Description                                                             |
| ----------------------- | ----------------------------------------------------------------------- |
| `total_queries`         | Valid queries processed                                                 |
| `udp_queries`           | UDP query count                                                         |
| `tcp_queries`           | TCP query count                                                         |
| `dot_queries`           | DNS-over-TLS query count                                                |
| `doh_queries`           | DNS-over-HTTPS query count                                              |
| `dropped_packets`       | Parse failures, invalid frames, and write errors                        |
| `parse_errors`          | DNS unpack failures                                                     |
| `write_errors`          | Response send failures                                                  |
| `refused_answers`       | REFUSED responses sent (ACL-denied recursion and other policy)          |
| `authoritative_answers` | Authoritative NOERROR / NODATA responses                                |
| `nxdomain_answers`      | NXDOMAIN responses sent                                                 |
| `forwarded_queries`     | Recursive queries successfully forwarded upstream                       |
| `upstream_failures`     | Recursive queries where all upstreams failed                            |
| `cache_hits`            | Forwarded queries served from the response cache                        |
| `cache_misses`          | Forwarded queries that missed the response cache                        |
| `acl_rejected`          | Recursive queries denied because the client IP is untrusted             |
| `truncated_responses`   | UDP responses truncated with TC set due to payload size limits          |
| `tcp_timeouts`          | TCP connections closed for failing to send a complete DNS frame in time |
| `firewall_blocked`      | Queries blocked by the DNS firewall blocklist engine                    |

`Stats.Snapshot()` and `Stats.MarshalJSON()` produce JSON-ready structs exposed via the management API (`GET /api/v1/stats`).

### Management API

A lightweight HTTP REST API (`internal/api`) runs alongside the DNS reactors. It uses the standard library `net/http` multiplexer with Bearer token authentication.

| Endpoint               | Method | Auth   | Description                                        |
| ---------------------- | ------ | ------ | -------------------------------------------------- |
| `/health`              | GET    | None   | Liveness probe; returns `{"status":"ok"}`          |
| `/api/v1/stats`        | GET    | Bearer | JSON snapshot of all `telemetry.Stats` counters    |
| `/api/v1/zones/reload` | POST   | Bearer | Force zone reload (same logic as fsnotify watcher) |

Configure the listener and token under `[api]` in `config.toml`. The default bind address is `127.0.0.1:8080` so the API is not exposed on all interfaces. For Docker or remote access, set `api.listen = '0.0.0.0:8080'` and publish the port in Compose.

```bash
curl -s http://127.0.0.1:8080/health
curl -s -H 'Authorization: Bearer dev-token-change-me' http://127.0.0.1:8080/api/v1/stats
curl -s -X POST -H 'Authorization: Bearer dev-token-change-me' http://127.0.0.1:8080/api/v1/zones/reload
```

The API shuts down gracefully with the DNS reactors on `SIGINT` or `SIGTERM`.

## Development Environment

The project ships a [Dev Containers](https://containers.dev/) configuration for Linux-native DNS development (privileged port 53, `SO_REUSEPORT`, and low-level socket work).

### Prerequisites

- Docker Engine with Linux container support
- Visual Studio Code or Cursor with the **Dev Containers** extension

### Quick Start

1. Open the repository root in VS Code / Cursor.
2. Run **Dev Containers: Reopen in Container** from the command palette.
3. Wait for the image build and `postCreateCommand` to finish.

### Container Details

| Item          | Value                                        |
| ------------- | -------------------------------------------- |
| Name          | `arx-dns-development`                        |
| Base image    | `golang:bookworm` (official Debian-based Go) |
| Workspace     | `/workspace/arx-dns`                         |
| User          | `vscode` (non-root, passwordless `sudo`)     |
| `CGO_ENABLED` | `0`                                          |

### Installed Utilities

- `dig`, `nslookup` — via `bind9-dnsutils` / `dnsutils`
- `git`, `curl`, `iproute2`, `iputils-ping`, `libcap2-bin`

### Networking and Port 53

The devcontainer is configured for DNS server development:

| Setting                                          | Purpose                                                |
| ------------------------------------------------ | ------------------------------------------------------ |
| `appPort` `53:53/udp` and `53:53/tcp`            | Publish DNS to the host                                |
| `forwardPorts` `53`                              | VS Code port forwarding for the DNS listener           |
| `--cap-add=NET_ADMIN`                            | Low-level network administration (routing, interfaces) |
| `--cap-add=NET_BIND_SERVICE`                     | Bind to privileged ports when capabilities are used    |
| `--sysctl=net.ipv4.ip_unprivileged_port_start=0` | Allow the `vscode` user to bind port 53 without root   |

**Windows host note:** If port 53 is already in use (for example by the DNS Client service or Hyper-V), stop the conflicting listener or change the host-side publish mapping before reopening the container.

### VS Code Extensions (auto-installed)

- `golang.go` — Go language server, build, and test integration
- `tamasfe.even-better-toml` — TOML configuration editing
- `yzhang.markdown-all-in-one` — Markdown authoring
- `davidanson.vscode-markdownlint` — Markdown linting
- `bierner.markdown-mermaid` — Mermaid diagrams in Markdown
