//go:build !webui

package api

import (
	"net/http"
	"strings"
)

func handleWebUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rel := strings.TrimPrefix(r.URL.Path, "/")
	if isReservedWebPath(rel) {
		http.NotFound(w, r)
		return
	}

	http.Error(w, "WebUI is not available in this build (rebuild with -tags webui)", http.StatusNotFound)
}
