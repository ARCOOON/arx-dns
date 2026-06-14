# arx-dns WebUI

Vue 3 management console for arx-dns. Embedded into the Go binary at build time.

## Stack

- Vue 3 + TypeScript + Vite
- Tailwind CSS v4
- shadcn-vue (radix-vue primitives)
- OKLCH theme tokens (light/dark)
- Noto Sans (headings) + Source Sans 3 (body) via Google Fonts

## Commands

```bash
npm install
npm run dev      # http://127.0.0.1:5173
npm run build    # outputs to dist/ (required before go build)
```

## Development API proxy

`vite.config.ts` proxies `/api` to `http://127.0.0.1:8080` during `npm run dev`. Start the Go management API listener before using authenticated views.

## Authentication

The API client (`src/api/client.ts`) reads `localStorage.getItem('arx_token')` and sends `Authorization: Bearer <token>` on every request. A `401` response clears the token and redirects to `/login`.

## Layout and views

| Path          | View       | Description                                               |
| ------------- | ---------- | --------------------------------------------------------- |
| `/`           | Dashboard  | Live telemetry cards polling `GET /api/v1/stats` every 2s |
| `/zones`      | Zones      | Placeholder for zone management                           |
| `/blocklists` | Blocklists | Placeholder for blocklist management                      |
| `/settings`   | Settings   | Placeholder for server settings                           |
| `/login`      | Login      | Bearer token entry (public route)                         |

## API modules

| Module              | Purpose                                                   |
| ------------------- | --------------------------------------------------------- |
| `src/api/client.ts` | Generic `fetch` wrapper with Bearer auth and 401 handling |
| `src/api/stats.ts`  | `StatsSnapshot` types and `fetchStats()` helper           |

## Adding components

```bash
npx shadcn-vue@latest add card
```

Components are placed under `src/components/ui/`.

## Go embedding

Production assets in `dist/` are embedded via `ui/embed.go` (`//go:embed all:dist`) and served by the management API at `/`.
