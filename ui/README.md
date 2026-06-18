# arx-dns WebUI

Vue 3 management console for arx-dns. Embedded into the Go binary at build time.

## Stack

- Vue 3 + TypeScript + Vite
- Tailwind CSS v4
- shadcn-vue (radix-vue primitives)
- chart.js + vue-chartjs (Dashboard live line charts)
- OKLCH theme tokens (light/dark)
- Noto Sans (headings) + Source Sans 3 (body) via Google Fonts

## Commands

```bash
npm install
npm install chart.js vue-chartjs   # required for Dashboard live charts
npm run dev      # http://127.0.0.1:5173
npm run build    # outputs to dist/ (required before go build)
```

## Development API proxy

`vite.config.ts` proxies `/api` to `http://127.0.0.1:8080` during `npm run dev`. Start the Go management API listener before using authenticated views.

## Authentication

The API client (`src/api/client.ts`) reads `localStorage.getItem('arx_token')` and sends `Authorization: Bearer <token>` on every request. A `401` response clears the token and redirects to `/login`.

## Layout and views

| Path          | View            | Description                                                                                                                                                                                                                                                                                                                                                             |
| ------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/`           | Dashboard       | Live telemetry cards (Total Queries with Local · Upstream breakdown and ratio bar), responsive `sm:grid-cols-2 xl:grid-cols-4` stat grid, time-window controls (Live / 5m / 1h / 30d), and rolling QPS / cache-hit charts with `HH:MM:SS` x-axis timestamps; Live mode polls `GET /api/v1/stats` every 2s, historical windows fetch once from SQLite rollup             |
| `/zones`      | Zones & Records | Zone sidebar with **Add Zone** (domain + **public/internal** view), color-coded view badges, record table (name + muted FQDN), reactive **Add/Edit Record** dialog (type-specific fields for MX/SRV/SOA; BIND TTL text input; SOA serial read-only), **AlertDialog** confirmation for zone and record delete, record update via `PUT /api/v1/zones/{zone}/records/{id}` |
| `/blocklists` | Blocklists      | Live `blocked_domains_count` stat card; **Remote Feeds** tab (source table with description sub-text, enable toggle, Domains / Last Sync columns, **Add Feed** dialog with optional description, **Update Feeds**); **Custom Rules** tab (manual domain table, **Add Domain** dialog, per-row delete; changes apply immediately)                                        |
| `/settings`   | Settings        | Placeholder for server settings                                                                                                                                                                                                                                                                                                                                         |
| `/login`      | Login           | Bearer token entry (public route)                                                                                                                                                                                                                                                                                                                                       |

## API modules

| Module                | Purpose                                                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `src/api/client.ts`   | Generic `fetch` wrapper with Bearer auth, zone list/record CRUD (including `PUT` record update), and zone create/delete helpers |
| `src/api/stats.ts`    | `StatsSnapshot` / `StatsHistoryPoint` types, `fetchStats()`, and `getStatsHistory()`                                            |
| `src/api/firewall.ts` | Blocklist source CRUD, custom domain CRUD, firewall status, and sync helpers                                                    |

## Adding components

```bash
npx shadcn-vue@latest add card
```

Components are placed under `src/components/ui/`.

## Go embedding

Production assets in `dist/` are embedded via `ui/embed_webui.go` (`//go:build webui`, `//go:embed all:dist`) and served by the management API at `/`. Core-only builds use `ui/embed_noui.go` (`//go:build !webui`) and do not require `dist/` to exist.

Build with the project Makefile:

```bash
make build-full    # auto-builds ui/dist when sources change
make build-core    # DNS server only, no WebUI
```
