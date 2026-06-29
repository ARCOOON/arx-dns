# arx-dns WebUI

Vue 3 management console for arx-dns. Embedded into the Go binary at build time.

## Stack

- Vue 3 + TypeScript + Vite
- Tailwind CSS v4
- shadcn-vue (reka-ui primitives; legacy radix-vue components retained)
- vue-sonner (toast notifications) + `useNotifications` composable (client-side history, max 50 entries)
- chart.js + vue-chartjs (Dashboard live line charts)
- OKLCH theme tokens (light/dark)
- Noto Sans (headings) + Source Sans 3 (body) via Google Fonts
- **pnpm** (`packageManager`: `pnpm@11.9.0`; requires Node.js 22+)
- Global content-addressable store at `~/.local/share/pnpm/store` (configured in `ui/.npmrc` and `ui/pnpm-workspace.yaml`; never committed under `.pnpm-store/`)

## Prerequisites

- Node.js 22+ (pnpm 11 requirement)
- pnpm 11 (`npm install -g pnpm@latest` after upgrading Node, or use Corepack: `corepack enable`)

## Commands

```bash
pnpm install
pnpm run dev      # http://127.0.0.1:5173
pnpm run build    # outputs to dist/ (required before go build)
```

If a workspace-local `.pnpm-store/` appears (e.g. after a misconfigured install), remove it and reinstall:

```bash
rm -rf .pnpm-store node_modules
pnpm install
```

Route views are lazy-loaded via dynamic `import()` in `src/router/index.ts`, so Vite emits per-route chunks instead of one oversized bundle. `vite.config.ts` suppresses the upstream `@vueuse/core` `INVALID_ANNOTATION` Rolldown warning while keeping the default 500 kB chunk-size limit.

## Development API proxy

`vite.config.ts` proxies `/api` to `http://127.0.0.1:8080` during `pnpm run dev`. Start the Go management API listener before using authenticated views.

## Authentication

The API client (`src/api/client.ts`) reads `localStorage.getItem('arx_token')` and sends `Authorization: Bearer <token>` on every request. A `401` response clears the token and redirects to `/login`.

## Layout and views

| Path          | View            | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/`           | Dashboard       | Live telemetry cards (Total Queries with Local · Upstream breakdown and ratio bar), responsive `sm:grid-cols-2 xl:grid-cols-4` stat grid, time-window controls (Live / 5m / 1h / 30d), and rolling QPS / cache-hit charts with `HH:MM:SS` x-axis timestamps; Live mode polls `GET /api/v1/stats` every 2s, historical windows fetch once from SQLite rollup                                                                                                                                                                                                                                                                                                                    |
| `/zones`      | Zones & Records | Zone sidebar with **Add Zone** (domain + **public/internal** view), color-coded view badges, record table (name + muted FQDN), **Settings** dialog (cog icon) for per-zone ACL overrides (`allow_query`, `allow_transfer`), **View** dropdown menu (ellipsis trigger) with persistent **Show DNSSEC records** toggle (`localStorage` key `arx-dns-zones-show-dnssec`), reactive **Add/Edit Record** dialog (type-specific fields for MX/SRV/SOA; BIND TTL text input; SOA serial read-only), **AlertDialog** confirmation for zone and record delete, record update via `PUT /api/v1/zones/{zone}/records/{id}`                                                                |
| `/blocklists` | Blocklists      | Live `blocked_domains_count` stat card with async **Update Feeds** sync (`POST /api/v1/firewall/sync` returns `202`; UI polls `GET /api/v1/firewall/status` every 2.5 s for `sync_in_progress`, 120 s timeout); **Remote Feeds** tab (source table with description sub-text, enable toggle, Domains / Last Sync columns, **Add Feed** dialog); **Custom Rules** tab (manual domain table, **Add Domain** dialog, per-row delete; changes apply immediately)                                                                                                                                                                                                                   |
| `/logs`       | Logs            | Terminal-style live log console with SSE stream, level filter, auto-scroll (scrolls to bottom on initial history load), persistent **Word Wrap** toggle (`localStorage` key `logs-word-wrap`), and a **Settings** link to `/settings?tab=logging`                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `/audit`      | Audit Trail     | Management API mutation log (`GET /api/v1/audit`, up to 500 entries); human-readable action labels with tooltip technical details (method, path, status, success, record type); target column shows zone or resource context                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `/settings`   | Settings        | Tabbed configuration UI: **DNS & System** (resolver mode, dynamic upstream resolver table with add/delete dialog, rate limits via `GET/PUT /api/v1/config`), **Security & ACL** (match list groups table with add/edit/delete dialog; global `allow_query`, `allow_recursion`, and `allow_transfer` Popover multi-select token inputs with checkbox suggestions for keywords and match lists via `GET/PUT /api/v1/config/acl`; graceful fallback to empty ACL state on API failure), **Logging** (log level and rotation via config API), **UI Preferences** (toast notification position, browser-local only); persistent restart warning when `requires_restart` is returned |
| `/login`      | Login           | Bearer token entry (public route)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

## API modules

| Module                         | Purpose                                                                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `src/api/client.ts`            | Bearer client, zone/record CRUD, DNSSEC, and ACL config (`GET/PUT /api/v1/config/acl`)                                         |
| `src/api/stats.ts`             | `StatsSnapshot` / `StatsHistoryPoint` types, `fetchStats()`, and `getStatsHistory()`                                           |
| `src/api/firewall.ts`          | Blocklist source CRUD, custom domain CRUD, firewall status, and sync helpers                                                   |
| `src/api/logs.ts`              | Log history, SSE stream helper, and legacy `GET/PUT /api/v1/logs/config` helpers                                               |
| `src/api/settings.ts`          | Legacy SQLite query ACL rule CRUD (`/api/v1/settings/acl`; superseded by BIND-style `[acl]` policies in Settings Security tab) |
| `src/api/config.ts`            | Full server configuration `GET/PUT /api/v1/config`; `cloneAppConfig()` deep-clones reactive Vue state for safe PUT payloads    |
| `src/api/audit.ts`             | Audit trail `GET /api/v1/audit`                                                                                                |
| `src/utils/auditFormatting.ts` | Human-readable audit action labels and parsed technical detail rows for tooltips                                               |

## Notifications

- `src/composables/useNotifications.ts` — `notify(message, type)` wraps `vue-sonner` toasts and appends to a reactive `history` array (max 50 items)
- `src/components/NotificationCenter.vue` — floating action button (FAB) with popover history panel; FAB corner follows `localStorage` key `arx-ui-toast-position` (same as toast placement in Settings → UI Preferences)
- All views use `notify()` instead of calling `vue-sonner` directly; `App.vue` still mounts the global `<Toaster />`

## Adding components

`components.json` follows the current shadcn-vue schema (no `tsConfigPath` or `framework` keys).

```bash
pnpm dlx shadcn-vue@latest add card
pnpm dlx shadcn-vue@latest add tooltip
```

Components are placed under `src/components/ui/`.

## Go embedding

Production assets in `dist/` are embedded via `ui/embed_webui.go` (`//go:build webui`, `//go:embed all:dist`) and served by the management API at `/`. Core-only builds use `ui/embed_noui.go` (`//go:build !webui`) and do not require `dist/` to exist.

Build with the project Makefile:

```bash
make build-full    # auto-builds ui/dist when sources change
make build-core    # DNS server only, no WebUI
```
