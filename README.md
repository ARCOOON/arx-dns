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

| Path                  | Purpose                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `cmd/arx-dns/`        | Server entrypoint (CLI flags, signal handling, reactor startup)  |
| `internal/network/`   | gnet UDP/TCP reactors with `SO_REUSEPORT` and dual-stack bind    |
| `internal/dnsproc/`   | DNS message parse/serialize and authoritative response builder   |
| `internal/storage/`   | Thread-safe in-memory radix-tree zone store, BIND zone loader, and fsnotify hot-reload |
| `internal/telemetry/` | Lock-free atomic counters (`sync/atomic`) for operations stats   |

## Build & Run

```bash
go build -o arx-dns ./cmd/arx-dns/
./arx-dns   # binds 0.0.0.0:53 by default (use sudo or devcontainer for port 53)
```

### CLI Flags

| Flag      | Default   | Description                                            |
| --------- | --------- | ------------------------------------------------------ |
| `-listen` | `0.0.0.0` | IP address to bind to                                  |
| `-port`   | `53`      | UDP/TCP port to listen on                              |
| `-loops`  | `0`       | gnet event loops per protocol (`0` = one per CPU core) |
| `-zones`  | `./zones` | Directory containing BIND `.zone` files                |

Example:

```bash
./arx-dns -listen 127.0.0.1 -port 5353 -loops 4 -zones ./zones
```

On startup, all `*.zone` files in the zones directory are loaded into the in-memory radix tree. The zone apex is taken from the filename (e.g. `arx.local.zone` → origin `arx.local.`) or from a `$ORIGIN` directive inside the file. Malformed zone files are logged and skipped; the server continues with the remaining zones.

While the server is running, `fsnotify` watches the zones directory for `Create`, `Write`, and `Remove` events on `.zone` files. Changes are debounced for 500ms (to allow atomic file writes to finish), then all zone files are re-parsed into a brand-new radix tree and swapped in atomically via `sync/atomic.Value`. Lookups remain lock-free on the active tree pointer; reload events log the number of loaded zones and any parse errors as structured JSON.

The default `zones/arx.local.zone` ships a small demo zone for immediate testing:

| Name               | Type  | Value              |
| ------------------ | ----- | ------------------ |
| `router.arx.local` | A     | `10.10.0.1`        |
| `router.arx.local` | AAAA  | `fd00::1`          |
| `www.arx.local`    | CNAME | `router.arx.local` |

Valid incoming DNS queries receive an authoritative answer when the name exists, `NXDOMAIN` when the name is unknown, or `NOERROR` with an empty answer when the name exists but the requested type is absent.

Verify with:

```bash
dig @127.0.0.1 router.arx.local A
dig @127.0.0.1 www.arx.local CNAME +tcp
dig @127.0.0.1 unknown.example.com A   # NXDOMAIN
```

Graceful shutdown is triggered by `SIGINT` or `SIGTERM`. Final operational counters are logged as JSON on exit.

### Telemetry

`internal/telemetry.Stats` tracks:

| Field                   | Description                                      |
| ----------------------- | ------------------------------------------------ |
| `total_queries`         | Valid queries processed                          |
| `udp_queries`           | UDP query count                                  |
| `tcp_queries`           | TCP query count                                  |
| `dropped_packets`       | Parse failures, invalid frames, and write errors |
| `parse_errors`          | DNS unpack failures                              |
| `write_errors`          | Response send failures                           |
| `refused_answers`       | REFUSED responses sent (reserved for future use) |
| `authoritative_answers` | Authoritative NOERROR / NODATA responses         |
| `nxdomain_answers`      | NXDOMAIN responses sent                          |

`Stats.Snapshot()` and `Stats.MarshalJSON()` produce JSON-ready structs for a future management API.

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
