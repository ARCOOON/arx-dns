# arx-dns

High-performance, enterprise-grade DNS server for the ARX ecosystem. 

## Capabilities
- Authoritative and recursive DNS resolution.
- Native UDP/TCP handling on Port 53 with multi-core scaling.
- In-memory caching, split-horizon routing, and advanced threat mitigation (Response Rate Limiting, RPZ).
- Modern transport support (DoT, DoH, DoQ).

## Architecture
Strictly adheres to KISS and DRY principles. Operates without heavy third-party frameworks. Direct system-level socket management and strict RFC 1035 compliant binary parsing.
