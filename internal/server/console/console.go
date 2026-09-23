// Package console serves the embedded admin console.
package console

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var files embed.FS

// dist is the built console, rooted at dist/.
var dist = func() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}()

// Built reports whether the console assets are present in this binary.
func Built() bool {
	_, err := fs.Stat(dist, "index.html")
	return err == nil
}

// Handler serves the console, falling back to index.html so client-side routes
// work on a hard refresh.
func Handler() http.Handler {
	server := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if !Built() {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The console has not been built. Run `npm --prefix web run build`, then rebuild the server.\n"))
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			serveIndex(w)
			return
		}
		info, err := fs.Stat(dist, path)
		switch {
		case err == nil && !info.IsDir():
			if strings.HasPrefix(path, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			server.ServeHTTP(w, r)
		case strings.HasPrefix(path, "assets/"):
			// A missing hashed asset is a real 404, not a client-side route.
			http.NotFound(w, r)
		default:
			serveIndex(w)
		}
	})
}

func serveIndex(w http.ResponseWriter) {
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		http.Error(w, "console index is missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(index)
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// The console is only ever served over TLS, directly or behind a proxy
	// that terminates it; this tells a browser never to try plain HTTP, so a
	// network attacker cannot strip it on the first request of a visit.
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Referrer-Policy", "same-origin")
}
