package httpapi

import (
	"net/http"
	"strings"

	"github.com/demobank/atm-auth/internal/realtime"
	"github.com/demobank/atm-auth/internal/web"
	"github.com/rs/cors"
)

// NewRouter wires REST endpoints + the WebSocket endpoint with CORS.
func NewRouter(h *Handlers, hub *realtime.Hub) http.Handler {
	mux := http.NewServeMux()

	// REST
	mux.HandleFunc("/api/health", methodOnly("GET", h.Health))
	mux.HandleFunc("/api/audit", methodOnly("GET", h.Audit))
	mux.HandleFunc("/api/session", methodOnly("POST", h.CreateSession))
	mux.HandleFunc("/api/session/approve", methodOnly("POST", h.ApproveSession))
	mux.HandleFunc("/api/session/", func(w http.ResponseWriter, r *http.Request) {
		// Routes that share the /api/session/{id}... prefix
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

	// Static ATM simulator UI (embedded). Catch-all on "/" — only reached
	// for paths not matched by the more specific /api and /ws routes above.
	mux.Handle("/", web.Handler())

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	})
	return c.Handler(mux)
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
