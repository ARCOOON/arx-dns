//go:build webui

// Package ui provides the compiled management WebUI embedded into the arx-dns binary.
package ui

import "embed"

// Dist holds production assets from ui/dist (build with: make ui/dist or cd ui && npm run build).
//
//go:embed all:dist
var Dist embed.FS
