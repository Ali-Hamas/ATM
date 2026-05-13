package web

import (
	"bytes"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:static
var staticFS embed.FS

// Handler returns an http.Handler that serves the built ATM simulator at /.
// Falls back to index.html for unknown paths so client-side routing works.
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}

	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "" || clean == "." || clean == "index.html" {
			serveIndex(w, index)
			return
		}

		f, err := sub.Open(clean)
		if err != nil {
			// SPA fallback: unknown path → serve index.html
			serveIndex(w, index)
			return
		}
		defer f.Close()
		stat, err := f.Stat()
		if err != nil || stat.IsDir() {
			serveIndex(w, index)
			return
		}

		// Hashed asset filenames mean we can cache aggressively.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeContent(w, r, clean, stat.ModTime(), readSeeker(f))
	})
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(index)
}

// readSeeker wraps an fs.File into an io.ReadSeeker for http.ServeContent.
// embed.FS files implement io.ReadSeeker, but the fs.File interface doesn't
// expose it — so we read into memory (files are small, embedded at compile time).
func readSeeker(f fs.File) io.ReadSeeker {
	buf := new(bytes.Buffer)
	_, _ = io.Copy(buf, f)
	return bytes.NewReader(buf.Bytes())
}
