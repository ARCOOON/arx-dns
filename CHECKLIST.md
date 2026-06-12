# Specification Checklist: Enterprise-Grade Universal DNS Server

## 0. Project Scaffold & Tooling

- [x] **Devcontainer:** Production-ready `.devcontainer/` with Go bookworm image, DNS utilities, port 53 UDP/TCP forwarding, and `NET_ADMIN` / `NET_BIND_SERVICE` capabilities.

## 1. Network Layer & Core I/O

- [x] **Dual-Stack Support:** Native support for IPv4 and IPv6 across all interfaces (`[::]:53` with `IPV6_V6ONLY=0`).
- [x] **Protocol Support:** Concurrent handling of UDP and TCP on Port 53 (RFC 1035 length-prefixed TCP framing; UDP datagram receive).
- [ ] **High-Concurrency Engine:** Event-driven, non-blocking I/O architecture (using `epoll`, `kqueue`, or `io_uring`) to process millions of Queries Per Second (QPS).
- [x] **SO_REUSEPORT Implementation:** Kernel-level load balancing for multi-core scaling (`runtime.NumCPU()` sockets per protocol).
- [ ] **Connection Management:** TCP connection pooling, keep-alive timers, and protection against TCP resource exhaustion (e.g., Slowloris mitigation).

## 2. DNS Packet Parsing & Protocol Core

- [ ] **RFC 1035 Compliance:** Full binary parsing and serialization of DNS messages (Header, Question, Answer, Authority, Additional sections).
- [ ] **EDNS0 Support (RFC 6891):** Handling of extended payload sizes (>512 bytes), EDNS options, and Path MTU Discovery.
- [ ] **Comprehensive Record Type Support:** Native processing of:
  - [ ] Core: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR`.
  - [ ] Enterprise/Sec: `SRV`, `CAA`, `TLSA`, `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `SVCB`, `HTTPS`.
- [ ] **Unknown RR Handling:** Transparent routing and storage of unknown resource records (RFC 3597).
- [ ] **Compression Algorithm:** RFC-compliant message compression to minimize packet size.

## 3. Operational Modes (Hybrid Architecture)

- [ ] **Authoritative Mode:**
  - [ ] Parsing and validation of standard BIND zone files.
  - [ ] Dynamic Updates (RFC 2136) secured via TSIG.
  - [ ] Zone Transfers: Master/Slave replication via AXFR (RFC 5936) and incremental IXFR (RFC 1995) including `NOTIFY` (RFC 1996).
- [ ] **Recursive / Resolver Mode:**
  - [ ] Full iterative resolution starting from root servers (`named.root`).
  - [ ] QNAME Minimization (RFC 7816) for enhanced privacy.
- [ ] **Caching Engine:**
  - [ ] Thread-safe, in-memory caching with strict TTL enforcement.
  - [ ] Negative Caching (RFC 2308) for `NXDOMAIN` and `NODATA` responses.
  - [ ] Lockless cache eviction strategies (LRU or LFU).
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

- [ ] **Split-Horizon DNS:** Delivery of distinct zone views based on source IP ACLs (Internal vs. External).
- [ ] **GeoDNS / Topology Routing:** Location-based response resolution using GeoIP databases.
- [ ] **EDNS Client Subnet (ECS - RFC 7871):** Forwarding and processing of client subnets during recursive queries for optimized CDN routing.
- [ ] **Health Checking & Failover Engine:** Active probing of backend IPs (Ping, TCP, HTTP/HTTPS) with dynamic record adjustments when endpoints fail.
- [ ] **Load Balancing Policies:** Implementation of Round-Robin, Weighted Round-Robin, and Random selection algorithms.
- [ ] **Anycast Readiness:** Completely stateless UDP processing design to ensure stability behind BGP Anycast routing.

## 6. Defensive Security & Policy Enforcement

- [ ] **Response Rate Limiting (RRL):** Mitigation of DNS amplification and reflection DDoS attacks via IP/subnet rate limits.
- [ ] **Response Policy Zones (RPZ / DNS Firewall):** Real-time query matching against threat intelligence feeds (actions: Block, Drop, CNAME-Rewrite, NXDOMAIN).
- [ ] **Access Control Lists (ACLs):** Granular definitions for:
  - [ ] Authorized recursive clients.
  - [ ] Authorized zone transfer (AXFR/IXFR) peers.
  - [ ] Management/API access.
- [ ] **DNS Cookies (RFC 7873):** Protection against IP spoofing and cache poisoning attacks.

## 7. Storage Engine & Pluggable Backends

- [ ] **In-Memory Storage:** Highly optimized data structures (Radix Trees or Red-Black Trees) for ultra-fast RAM lookups.
- [ ] **Database Backends (Dynamic Zones):** Pluggable driver architecture for real-time relational (PostgreSQL, MySQL) and NoSQL/KV-Store (Redis, etcd) integration.
- [ ] **Directory Integration:** LDAP/Active Directory bindings for automated IPAM (IP Address Management) synchronization.

## 8. Management, Automation & Observability

- [ ] **API-First Design:** Complete REST or gRPC interface for zero-downtime CRUD operations on records and zones.
- [ ] **Prometheus Metrics Exporter:** Native endpoint exposing:
  - [ ] Query statistics (QPS split by UDP/TCP/DoH/DoT/DoQ).
  - [ ] Latency histograms.
  - [ ] Cache hit/miss ratios.
  - [ ] Error code rates (`NXDOMAIN`, `SERVFAIL`, `REFUSED`).
- [ ] **Structured Logging:** JSON-formatted output to `stdout` or `syslog` with adjustable verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`).
- [ ] **Audit Trail:** Immutable logging of all administrative actions and API mutations.
