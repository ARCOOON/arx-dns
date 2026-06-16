//go:build !webui

// Package ui is a stub in core-only builds; the management WebUI is not embedded.
package ui

import "io/fs"

// Dist is nil when the binary is built without the webui tag.
var Dist fs.FS
