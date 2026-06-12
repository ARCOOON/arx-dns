# Specification Checklist: Enterprise-Grade Universal DNS Server

## 0. Project Scaffold & Tooling

- [x] **Devcontainer:** Production-ready `.devcontainer/` with Go bookworm image, DNS utilities, port 53 UDP/TCP forwarding, and `NET_ADMIN` / `NET_BIND_SERVICE` capabilities.

## 1. Network Layer & Core I/O

- [x] **Dual-Stack Support:** Native support for IPv4 and IPv6 across all interfaces (`[::]:53` with `IPV6_V6ONLY=0`).
- [x] **Protocol Support:** Concurrent handling of UDP and TCP on Port 53 (RFC 1035 length-prefixed TCP framing; UDP datagram receive).
- [x] **High-Concurrency Engine:** Event-driven, non-blocking I/O architecture (using `epoll`, `kqueue`, or `io_uring`) to process millions of Queries Per Second (QPS).
- [x] **SO_REUSEPORT Implementation:** Kernel-level load balancing for multi-core scaling (`runtime.NumCPU()` sockets per protocol).
- [x] **Connection Management:** TCP keep-alive (`WithTCPKeepAlive`), 3-second read-frame timeout with OnTick sweep, and Slowloris mitigation via forced connection close (Phase 10).

## 2. DNS Packet Parsing & Protocol Core

- [x] **RFC 1035 Compliance:** Full binary parsing and serialization of DNS messages (Header, Question, Answer, Authority, Additional sections).
- [x] **EDNS0 Support (RFC 6891):** OPT detection, negotiated UDP payload truncation with TC bit, and OPT echo in responses (Phase 10). EDNS options and Path MTU Discovery remain open.
- [ ] **Comprehensive Record Type Support:** Native processing of:
  - [~] Core: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR` (`A`, `AAAA`, `CNAME` authoritative lookup in Phase 03; CNAME chain following for `A`/`AAAA` in Phase 06).
  - [ ] Enterprise/Sec: `SRV`, `CAA`, `TLSA`, `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `SVCB`, `HTTPS`.
- [ ] **Unknown RR Handling:** Transparent routing and storage of unknown resource records (RFC 3597).
- [ ] **Compression Algorithm:** RFC-compliant message compression to minimize packet size.

## 3. Operational Modes (Hybrid Architecture)

- [ ] **Authoritative Mode:**
  - [x] In-memory authoritative resolution with radix-tree storage and NXDOMAIN for unknown names (Phase 03).
  - [x] CNAME chain following for `A`/`AAAA` queries with loop protection and depth limit (Phase 06).
  - [x] Parsing and validation of standard BIND zone files (Phase 04).
  - [x] fsnotify hot-reload with atomic radix-tree swapping and 500ms debounce (Phase 05).
  - [ ] Dynamic Updates (RFC 2136) secured via TSIG.
  - [ ] Zone Transfers: Master/Slave replication via AXFR (RFC 5936) and incremental IXFR (RFC 1995) including `NOTIFY` (RFC 1996).
- [ ] **Recursive / Resolver Mode:**
  - [x] Upstream forwarding for queries outside local zones when RD is set, with sequential fallback and 2s timeout per upstream (Phase 07).
  - [x] TTL-aware in-memory cache for forwarded upstream responses with hit/miss telemetry (Phase 08).
  - [ ] Full iterative resolution starting from root servers (`named.root`).
  - [ ] QNAME Minimization (RFC 7816) for enhanced privacy.
- [ ] **Caching Engine:**
  - [x] Thread-safe, in-memory caching with strict TTL enforcement for forwarded upstream responses (Phase 08, Ristretto).
  - [ ] Negative Caching (RFC 2308) for `NXDOMAIN` and `NODATA` responses.
  - [x] Lockless cache eviction strategies (LRU or LFU) via Ristretto TinyLFU (Phase 08).
  - [ ] Infrastructure caching (RTT tracking of upstream nameservers for optimal path selection).

## 4. Encrypted DNS & Security

- [ ] **DNS-over-TLS (DoT):** Implementation via RFC 7858 using TLS 1.3 with session resumption.
- [ ] **DNS-over-HTTPS (DoH):** Implementation via RFC 8484 (HTTP/2 and HTTP/3 support).
- [ ] **DNS-over-QUIC (DoQ):** Implementation via RFC 9250 for minimal latency and elimination of head-of-line blocking.
- [ ] **DNSSEC Suite:**
  - [ ] On-the-fly cryptographic validation for recursive queries (chain of trust verification).
  - [ ] Automated inline zone signing for authoritative mode (ZSK/KSK management).
  - [ ] NSEC/NSEC3 generation for authenticated denial of existence.

## 5. Advanced Traffic Management & Routing

- [x] **Split-Horizon DNS:** Delivery of distinct zone views based on source IP ACLs (Internal vs. External) (Phase 09).
- [ ] **GeoDNS / Topology Routing:** Location-based response resolution using GeoIP databases.
- [ ] **EDNS Client Subnet (ECS - RFC 7871):** Forwarding and processing of client subnets during recursive queries for optimized CDN routing.
- [ ] **Health Checking & Failover Engine:** Active probing of backend IPs (Ping, TCP, HTTP/HTTPS) with dynamic record adjustments when endpoints fail.
- [ ] **Load Balancing Policies:** Implementation of Round-Robin, Weighted Round-Robin, and Random selection algorithms.
- [ ] **Anycast Readiness:** Completely stateless UDP processing design to ensure stability behind BGP Anycast routing.

## 6. Defensive Security & Policy Enforcement

- [ ] **Response Rate Limiting (RRL):** Mitigation of DNS amplification and reflection DDoS attacks via IP/subnet rate limits.
- [ ] **Response Policy Zones (RPZ / DNS Firewall):** Real-time query matching against threat intelligence feeds (actions: Block, Drop, CNAME-Rewrite, NXDOMAIN).
- [x] **Access Control Lists (ACLs):** Granular definitions for:
  - [x] Authorized recursive clients (`-trusted-subnets`, REFUSED for untrusted RD queries) (Phase 09).
  - [ ] Authorized zone transfer (AXFR/IXFR) peers.
  - [ ] Management/API access.
- [ ] **DNS Cookies (RFC 7873):** Protection against IP spoofing and cache poisoning attacks.

## 7. Storage Engine & Pluggable Backends

- [x] **In-Memory Storage:** Thread-safe dual-view radix-tree store (`github.com/armon/go-radix`) for authoritative FQDN lookups with separate public and internal views and `sync/atomic.Value` tree swapping for lock-free reads (Phase 09).
- [x] **Zone Hot-Reload:** `fsnotify` watcher on the `-zones` directory and `zones/internal/` with debounced full reload and structured `slog` logging (Phase 09).
- [ ] **Database Backends (Dynamic Zones):** Pluggable driver architecture for real-time relational (PostgreSQL, MySQL) and NoSQL/KV-Store (Redis, etcd) integration.
- [ ] **Directory Integration:** LDAP/Active Directory bindings for automated IPAM (IP Address Management) synchronization.

## 8. Management, Automation & Observability

- [ ] **API-First Design:** Complete REST or gRPC interface for zero-downtime CRUD operations on records and zones.
- [x] **Internal Telemetry (Phase 02):** Lock-free `sync/atomic` counters for query totals, UDP/TCP split, dropped packets, REFUSED answers, ACL rejections, forwarded queries, upstream failures, cache hits/misses, truncated UDP responses, and TCP read timeouts (JSON-serializable snapshot for future API).
- [ ] **Prometheus Metrics Exporter:** Native endpoint exposing:
  - [ ] Query statistics (QPS split by UDP/TCP/DoH/DoT/DoQ).
  - [ ] Latency histograms.
  - [ ] Cache hit/miss ratios.
  - [ ] Error code rates (`NXDOMAIN`, `SERVFAIL`, `REFUSED`).
- [ ] **Structured Logging:** JSON-formatted output to `stdout` or `syslog` with adjustable verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`).
- [ ] **Audit Trail:** Immutable logging of all administrative actions and API mutations.
