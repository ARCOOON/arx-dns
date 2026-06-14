# Specification Checklist: Enterprise-Grade Universal DNS Server

## 0. Project Scaffold & Tooling

- [x] **Devcontainer:** Production-ready `.devcontainer/` with Go bookworm image, DNS utilities, port 53 UDP/TCP forwarding, and `NET_ADMIN` / `NET_BIND_SERVICE` capabilities.
- [x] **Docker deployment (Phase 13):** Multi-stage `Dockerfile` (`golang:bookworm` builder, `scratch` runtime, `CGO_ENABLED=0`), `docker-compose.yml` with ports 53 UDP/TCP, 853 TCP (DoT), and 443 TCP (DoH), host `data/` volume mounts including `./data/certs`, `unless-stopped` restart, and `NET_ADMIN` / `NET_BIND_SERVICE` capabilities; Buildx-ready for `linux/amd64` and `linux/arm64`.

## 1. Network Layer & Core I/O

- [x] **Dual-Stack Support:** Native support for IPv4 and IPv6 across all interfaces (`[::]:53` with `IPV6_V6ONLY=0`).
- [x] **Protocol Support:** Concurrent handling of UDP and TCP on Port 53 (RFC 1035 length-prefixed TCP framing; UDP datagram receive).
- [x] **High-Concurrency Engine:** Event-driven, non-blocking I/O architecture (using `epoll`, `kqueue`, or `io_uring`) to process millions of Queries Per Second (QPS).
- [x] **SO_REUSEPORT Implementation:** Kernel-level load balancing for multi-core scaling (`runtime.NumCPU()` sockets per protocol).
- [x] **Connection Management:** TCP keep-alive (`WithTCPKeepAlive`), 3-second read-frame timeout with OnTick sweep, and Slowloris mitigation via forced connection close (Phase 10).

## 2. DNS Packet Parsing & Protocol Core

- [x] **RFC 1035 Compliance:** Full binary parsing and serialization of DNS messages (Header, Question, Answer, Authority, Additional sections).
- [x] **EDNS0 Support (RFC 6891):** OPT detection, negotiated UDP payload truncation with TC bit, and OPT echo in responses (Phase 10). EDNS options beyond DNS Cookies and Path MTU Discovery remain open.
- [x] **Comprehensive Record Type Support:** Native processing of:
  - [x] Core: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR` (`A`, `AAAA`, `CNAME` authoritative lookup in Phase 03; CNAME chain following for `A`/`AAAA` in Phase 06; `MX`/`TXT` API CRUD and BIND serialization in Phase 18; `NS`/`SOA`/`PTR` API validation and BIND serialization in Phase 24).
  - [x] Enterprise/Sec: `SRV`, `CAA`, `SVCB`, `HTTPS` (`RRSIG`/`DNSKEY` validation on forwarded responses in Phase 16; `SRV` API CRUD and BIND serialization in Phase 18; `CAA`/`SVCB`/`HTTPS` API validation and BIND serialization in Phase 24). `TLSA`, `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3` remain open for authoritative signing.
- [x] **Unknown RR Handling:** Transparent routing and storage of unknown resource records (RFC 3597) via `TYPE<id>` and `\# <length> <hex>` BIND syntax (Phase 24).
- [x] **ANY Query Mitigation (RFC 8482):** QTYPE 255 returns a minimal authoritative answer (zone SOA or synthesized HINFO) with TC set; full RRset enumeration is not performed (Phase 24).
- [x] **Compression Algorithm:** RFC 1035 name compression enabled on every outgoing response via `dns.Msg.Compress = true` in `packResponse` (Phase 26).

## 3. Operational Modes (Hybrid Architecture)

- [x] **Authoritative Mode:**
  - [x] In-memory authoritative resolution with radix-tree storage and NXDOMAIN for unknown names (Phase 03).
  - [x] CNAME chain following for `A`/`AAAA` queries with loop protection and depth limit (Phase 06).
  - [x] Parsing and validation of standard BIND zone files (Phase 04).
  - [x] fsnotify hot-reload with atomic radix-tree swapping and 500ms debounce (Phase 05).
  - [x] Dynamic Updates (RFC 2136) secured via TSIG.
  - [x] Zone Transfers: Master/Slave replication via AXFR (RFC 5936) and incremental IXFR (RFC 1995) including `NOTIFY` (RFC 1996) (Phase 28).
- [x] **Recursive / Resolver Mode:**
  - [x] Upstream forwarding for queries outside local zones when RD is set, with sequential fallback and 2s timeout per upstream (Phase 07).
  - [x] TTL-aware in-memory cache for recursive responses with hit/miss telemetry (Phase 08).
  - [x] ECS-aware cache keys for forwarded upstream responses (Phase 23).
  - [x] Negative Caching (RFC 2308) for `NXDOMAIN` and `NODATA` recursive responses (Phase 19).
  - [x] Full iterative resolution starting from root servers with delegation walking, glue/sub-query NS resolution, depth limit, and Ristretto cache integration (Phase 29).
  - [x] QNAME Minimization (RFC 7816) for enhanced privacy with SERVFAIL/REFUSED/timeout fallback and `qname_min_fallbacks` telemetry (Phase 30).
- [x] **Caching Engine:**
  - [x] Thread-safe, in-memory caching with strict TTL enforcement for forwarded upstream responses (Phase 08, Ristretto).
  - [x] Negative Caching (RFC 2308) for `NXDOMAIN` and `NODATA` responses with SOA-derived TTL (Phase 19).
  - [x] Lockless cache eviction strategies (LRU or LFU) via Ristretto TinyLFU (Phase 08).
  - [x] Infrastructure caching (RTT tracking): EWMA-smoothed per-IP RTT registry with failure penalties, stale-entry sweep, fastest-first upstream/root-hint selection in forwarder and iterative resolver, and `rtt_tracked_ips` telemetry (Phase 31).

## 4. Encrypted DNS & Security

- [x] **DNS-over-TLS (DoT):** RFC 7858 listener on configurable `:853` with TLS 1.2+, ALPN `dot`, and RFC 1035 length-prefixed TCP framing routed to `dnsproc.Processor` (Phase 14).
- [x] **DNS-over-HTTPS (DoH):** RFC 8484 `GET`/`POST /dns-query` with `application/dns-message` on configurable `:443` over TLS (Phase 14).
- [ ] **DNS-over-QUIC (DoQ):** Implementation via RFC 9250 for minimal latency and elimination of head-of-line blocking.
- [ ] **DNSSEC Suite:**
  - [x] On-the-fly cryptographic validation for forwarded upstream responses (`RRSIG`/`DNSKEY` verification, AD bit, BOGUS → SERVFAIL) (Phase 16).
  - [ ] Full chain-of-trust verification from root trust anchors.
  - [ ] Automated inline zone signing for authoritative mode (ZSK/KSK management).
  - [ ] NSEC/NSEC3 generation for authenticated denial of existence.

## 5. Advanced Traffic Management & Routing

- [x] **Split-Horizon DNS:** Delivery of distinct zone views based on source IP ACLs (Internal vs. External) (Phase 09).
- [ ] **GeoDNS / Topology Routing:** Location-based response resolution using GeoIP databases.
- [x] **EDNS Client Subnet (ECS - RFC 7871):** Forwarding and processing of client subnets during recursive queries for optimized CDN routing (Phase 23).
- [ ] **Health Checking & Failover Engine:** Active probing of backend IPs (Ping, TCP, HTTP/HTTPS) with dynamic record adjustments when endpoints fail.
- [ ] **Load Balancing Policies:** Implementation of Round-Robin, Weighted Round-Robin, and Random selection algorithms.
- [ ] **Anycast Readiness:** Completely stateless UDP processing design to ensure stability behind BGP Anycast routing.

## 6. Defensive Security & Policy Enforcement

- [x] **Response Rate Limiting (RRL):** Per-client-IP token-bucket rate limiting via `golang.org/x/time/rate`, silent packet drop on exceed (no SERVFAIL/REFUSED), configurable `[rate_limit]` section, stale-entry sweep, and `rrl_dropped` telemetry (Phase 21).
- [ ] **Response Policy Zones (RPZ / DNS Firewall):** Real-time query matching against threat intelligence feeds (actions: Block, Drop, CNAME-Rewrite, NXDOMAIN).
  - [x] Flat-file blocklist engine with reversed-domain radix prefix matching, subdomain blocking, `NXDOMAIN` / `ZEROIP` actions, fsnotify hot-reload, and `firewall_blocked` telemetry (Phase 11).
- [x] **Access Control Lists (ACLs):** Granular definitions for:
  - [x] Authorized recursive clients (`recursive.trusted_subnets`, REFUSED for untrusted RD queries) (Phase 09).
  - [x] Authorized zone transfer (AXFR/IXFR) peers (`xfr.allowed_subnets`, REFUSED for unauthorized TCP transfers; UDP AXFR/IXFR refused) (Phase 28).
  - [x] Management/API access.
    - [x] Bearer-token management API on `[api]` listener (Phase 15).
    - [x] Optional HTTPS (`api.tls_cert` / `api.tls_key`) for Bearer token protection in transit (Phase 18).
    - [x] Zone URL parameter validation against path traversal (Phase 18).
- [x] **DNS Cookies (RFC 7873):** HMAC-SHA256 server cookie generation, Client/Server Cookie verification, BADCOOKIE rejection with truncated answers, `[security]` config (`dns_cookies_enabled`, `dns_cookie_secret` auto-generation), and `cookies_verified` / `cookies_rejected` telemetry (Phase 22).

## 7. Storage Engine & Pluggable Backends

- [x] **In-Memory Storage:** Thread-safe dual-view radix-tree store (`github.com/armon/go-radix`) for authoritative FQDN lookups with separate public and internal views and `sync/atomic.Value` tree swapping for lock-free reads (Phase 09).
- [x] **Zone Hot-Reload:** `fsnotify` watcher on the zones directory and `zones/internal/` with debounced full reload and structured `slog` logging (Phase 09).
- [ ] **Database Backends (Dynamic Zones):** Pluggable driver architecture for real-time relational (PostgreSQL, MySQL) and NoSQL/KV-Store (Redis, etcd) integration.
- [ ] **Directory Integration:** LDAP/Active Directory bindings for automated IPAM (IP Address Management) synchronization.

## 8. Management, Automation & Observability

- [x] **Unified TOML Configuration:** Single `config.toml` file with auto-generation on first start; `[tls]` and `[listeners]` sections for encrypted DNS; `[security]` section for DNSSEC validation and DNS Cookies; `[ecs]` section for EDNS Client Subnet forwarding; `[resolver]` section for forward vs iterative recursive mode and root hints; `[xfr]` section for zone transfer ACLs and NOTIFY slaves; all legacy CLI flags migrated to typed `internal/config` struct (Phase 12, Phase 14, Phase 16, Phase 22, Phase 23, Phase 28, Phase 29).

- [~] **API-First Design:** Complete REST or gRPC interface for zero-downtime CRUD operations on records and zones.
  - [x] Health, telemetry stats, and manual zone reload endpoints (Phase 15).
  - [x] Zone listing and authenticated record create/delete with BIND `.zone` file persistence (Phase 17).
  - [x] Advanced record types (`MX`, `TXT`, `SRV`) with validation and BIND zone re-writer support (Phase 18).
  - [x] API TLS (HTTPS) and audit logging for `POST`/`DELETE` mutations (Phase 18).

- [x] **Internal Telemetry (Phase 02):** Lock-free `sync/atomic` counters for query totals, UDP/TCP split, dropped packets, REFUSED answers, ACL rejections, forwarded queries, upstream failures, cache hits/misses, negative cache hits, truncated UDP responses, TCP read timeouts, firewall-blocked queries, DNSSEC validation pass/fail counters, RRL-dropped queries, DNS Cookie verified/rejected counters, ECS-forwarded query counter, AXFR completed/refused counters, NOTIFY sent/failed counters, QNAME minimization fallback counter, and RTT registry size (`rtt_tracked_ips`) (JSON-serializable snapshot for future API).
- [x] **Management HTTP API (Phase 15):** `net/http` REST API on configurable `[api]` listener with Bearer token auth; unauthenticated `GET /health`, authenticated `GET /api/v1/stats` and `POST /api/v1/zones/reload`; graceful shutdown with DNS reactors.
- [x] **Zone & Record Management API (Phase 17):** Authenticated `GET /api/v1/zones`, `POST /api/v1/zones/{zone}/records`, and `DELETE /api/v1/zones/{zone}/records`; atomic radix-tree swap on mutation; BIND `.zone` file rewrite via `internal/storage` writer with atomic rename.
- [x] **API Security Hardening (Phase 18):** Optional `[api]` TLS (`tls_cert`, `tls_key`); strict `{zone}` FQDN validation; structured `slog` audit trail for all `POST` and `DELETE` requests.
- [x] **Prometheus Metrics Exporter (Phase 20):** Native `GET /metrics` endpoint (unauthenticated) exposing all `telemetry.Stats` atomic counters via a custom Prometheus `Collector` that reads values only on scrape; `promhttp` handler on the management API listener.
- [ ] **Structured Logging:** JSON-formatted output to `stdout` or `syslog` with adjustable verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`).
- [x] **Audit Trail:** Immutable logging of all administrative actions and API mutations (`POST`/`DELETE` audit middleware with client IP, zone, action, status) (Phase 18).