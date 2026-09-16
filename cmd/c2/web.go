package main

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed web
var webFS embed.FS

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if strings.HasPrefix(path, "web/") {
		path = strings.TrimPrefix(path, "web/")
	}
	content, err := webFS.ReadFile("web/" + path)
	if err != nil {
		// single page app fallback
		index, ierr := webFS.ReadFile("web/index.html")
		if ierr != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
		return
	}
	w.Header().Set("Content-Type", mimeFor(path))
	w.Write(content)
}

func mimeFor(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".ico"):
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}
