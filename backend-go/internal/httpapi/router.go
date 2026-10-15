package httpapi

import (
	"net/http"
	"strings"

	"github.com/demobank/atm-auth/internal/realtime"
	"github.com/demobank/atm-auth/internal/web"
	"github.com/rs/cors"
)

// NewRouter wires REST endpoints + the WebSocket endpoint with bank-grade security headers & CORS.
func NewRouter(h *Handlers, hub *realtime.Hub) http.Handler {
	mux := http.NewServeMux()

	// REST
	mux.HandleFunc("/api/health", methodOnly("GET", h.Health))
	mux.HandleFunc("/api/audit", methodOnly("GET", h.Audit))
	mux.HandleFunc("/api/session", methodOnly("POST", h.CreateSession))
	mux.HandleFunc("/api/session/approve", methodOnly("POST", h.ApproveSession))
	mux.HandleFunc("/api/session/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/session/")
		switch {
		case strings.HasSuffix(rest, "/consume"):
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			h.ConsumeSession(w, r)
		default:
			if r.Method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			h.GetSession(w, r)
		}
	})

	// WebSocket
	mux.Handle("/ws", hub)

	// Static ATM simulator UI (embedded). Catch-all on "/"
	mux.Handle("/", web.Handler())

	// CORS lockdown: only allowed origins (default to localhost/127.0.0.1 or bank configured domains)
	allowedOrigins := h.Cfg.AllowedOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:4000", "http://127.0.0.1:4000"}
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Device-Id", "X-Atm-Id"},
		AllowCredentials: true,
	})

	// Wrap with bank security headers middleware
	return securityHeadersMiddleware(c.Handler(mux))
}

// securityHeadersMiddleware adds enterprise HTTP headers to satisfy OWASP and pen-test audits
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HSTS: force HTTPS for 2 years
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// Prevent MIME-sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking / framing
		w.Header().Set("X-Frame-Options", "DENY")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:;")

		// XSS Auditor
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Remove server banner if any
		w.Header().Del("Server")

		next.ServeHTTP(w, r)
	})
}

func methodOnly(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}
