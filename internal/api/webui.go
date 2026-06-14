package api

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/ARCOOON/arx-dns/ui"
)

var webUIRoot fs.FS

func init() {
	sub, err := fs.Sub(ui.Dist, "dist")
	if err != nil {
		webUIRoot = fs.FS(nil)
		return
	}
	webUIRoot = sub
}

func newWebUIHandler() http.Handler {
	if webUIRoot == nil {
		return http.NotFoundHandler()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWebUIFile(w, r, strings.TrimPrefix(path.Clean(r.URL.Path), "/"))
	})
}

func serveWebUIFile(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" || name == "." || name == "/" {
		name = "index.html"
	}

	data, err := fs.ReadFile(webUIRoot, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && name != "index.html" {
			serveWebUIFile(w, r, "index.html")
			return
		}
		http.NotFound(w, r)
		return
	}

	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if strings.HasSuffix(name, ".html") {
		contentType = "text/html; charset=utf-8"
	}

	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func isReservedWebPath(path string) bool {
	switch {
	case path == "health",
		path == "metrics",
		strings.HasPrefix(path, "api/"):
		return true
	default:
		return false
	}
}

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

	newWebUIHandler().ServeHTTP(w, r)
}
