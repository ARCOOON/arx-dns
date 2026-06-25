# arx-dns

High-performance, enterprise-grade DNS server for the ARX ecosystem.

## Quickstart

```bash
make build-full
./arx-dns
dig @127.0.0.1 router.arx.local A
```

| Command | Description |
| ------- | ----------- |
| `make build-full` | Binary with embedded WebUI |
| `make build-core` | Binary without WebUI (`-tags noui`) |
| `make help` | All build targets |

Docker: `docker compose up -d --build`

## Documentation

**All technical documentation lives in the [`wiki/`](wiki/) submodule** (architecture, API reference, development guide, roadmap).

```bash
git submodule update --init wiki
```

Browse locally: [`wiki/Home.md`](wiki/Home.md) · [GitHub wiki](https://github.com/ARCOOON/arx-dns/wiki)
