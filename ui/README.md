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

## Adding components

```bash
npx shadcn-vue@latest add card
```

Components are placed under `src/components/ui/`.

## Go embedding

Production assets in `dist/` are embedded via `ui/embed.go` (`//go:embed all:dist`) and served by the management API at `/`.
