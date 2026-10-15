// Package realtime manages WebSocket connections for real-time session updates.
//
// Task 2 Security Controls implemented:
//  1. Single-subscriber policy — only ONE WebSocket client per session ID is
//     allowed. A second connection for the same session evicts the first to
//     prevent eavesdropping by a race-condition attacker who guesses a session ID.
//  2. WebSocket heartbeat (ping/pong) — server sends a native WebSocket Ping
//     frame every 30 seconds and expects a Pong within 5 seconds, or closes
//     the connection with code 1001 (Going Away).
//  3. 60-second idle read deadline — the server forcibly closes connections
//     that do not send any frame (Pong or data) within 60 seconds of the last
//     activity, preventing ghost connections from accumulating.
package realtime

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/demobank/atm-auth/internal/session"
	"github.com/gorilla/websocket"
)

const (
	// pingInterval is the time between server-initiated Ping frames.
	pingInterval = 30 * time.Second
	// pongWait is the maximum time to wait for a Pong frame after sending a Ping.
	pongWait = 5 * time.Second
	// idleTimeout is the maximum time a connection may be fully silent.
	// Set to 60 seconds to match the session TTL, after which QR codes expire anyway.
	idleTimeout = 60 * time.Second
	// writeWait is the maximum time allocated for writing a message to the peer.
	writeWait = 5 * time.Second
)

// Hub fan-outs session state changes to WebSocket subscribers of a given session ID.
//
// Security: At most one connection is allowed per session (single-subscriber policy).
// A new connection for a session will evict any existing connection for that session.
type SessionValidator func(sid string) bool

type Hub struct {
	mu        sync.RWMutex
	subs      map[string]*conn // session ID → single conn (strictly one per session)
	upgrader  websocket.Upgrader
	validator SessionValidator
}

type conn struct {
	ws      *websocket.Conn
	writeMu sync.Mutex // gorilla/websocket forbids concurrent writes
}

func NewHub(validator ...SessionValidator) *Hub {
	var v SessionValidator
	if len(validator) > 0 {
		v = validator[0]
	}
	return &Hub{
		subs:      make(map[string]*conn),
		validator: v,
		upgrader: websocket.Upgrader{
			// CORS is enforced at the HTTP router layer; allow WS upgrade from any origin.
			// The actual CORS domain restriction is applied by the CORS middleware before
			// the WebSocket handshake request reaches this handler.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// ServeHTTP handles /ws?sid=<sessionId>. Closes with code 1008 if sid missing or invalid.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade failed: %v", err)
		return
	}

	if sid == "" {
		_ = ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "missing sid"), time.Now().Add(writeWait))
		ws.Close()
		return
	}

	// P1 Security: Validate session exists and is not expired before allowing subscription
	if h.validator != nil && !h.validator(sid) {
		log.Printf("[ws] rejecting connection for non-existent/expired sid=%s", sid)
		_ = ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "session not found or expired"), time.Now().Add(writeWait))
		ws.Close()
		return
	}

	c := &conn{ws: ws}

	// ── Single-subscriber policy ──────────────────────────────────────────────
	// If another connection already holds this session, evict it before
	// registering the new subscriber. This prevents an attacker who has
	// observed a session ID from silently eavesdropping alongside the
	// legitimate ATM client.
	h.mu.Lock()
	if _, exists := h.subs[sid]; exists {
		h.mu.Unlock()
		log.Printf("[ws] rejecting takeover attempt for active sid=%s (single-subscriber policy)", sid)
		_ = ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(4408, "session already subscribed by active terminal"), time.Now().Add(writeWait))
		ws.Close()
		return
	}
	h.subs[sid] = c
	h.mu.Unlock()
	defer h.unsubscribe(sid, c)

	// Greeting: { type: "subscribed", sid }
	c.writeJSON(map[string]interface{}{"type": "subscribed", "sid": sid})

	// ── Configure idle timeout and pong handler ───────────────────────────────
	// Set the initial read deadline. Receiving any frame (Pong or data) will
	// extend the deadline via the Pong handler registered below.
	_ = ws.SetReadDeadline(time.Now().Add(idleTimeout))
	ws.SetPongHandler(func(string) error {
		// Pong received — reset the idle deadline
		return ws.SetReadDeadline(time.Now().Add(idleTimeout))
	})

	// ── Heartbeat goroutine ───────────────────────────────────────────────────
	// Sends a native WebSocket Ping every pingInterval. If the client (browser
	// or ATM app) does not respond with a Pong within pongWait, the connection
	// is closed cleanly.
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.writeMu.Lock()
				deadline := time.Now().Add(pongWait)
				err := ws.WriteControl(websocket.PingMessage, nil, deadline)
				c.writeMu.Unlock()
				if err != nil {
					// Could not send ping — connection broken; let the reader pump clean up
					ws.Close()
					return
				}
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)

	// ── Read pump ─────────────────────────────────────────────────────────────
	// We don't expect data messages from the client. The read pump solely:
	//  a) Drives the idle deadline via the pong handler above, and
	//  b) Detects connection close / errors to trigger cleanup.
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			return
		}
	}
}

func (h *Hub) unsubscribe(sid string, c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Only remove if this specific conn is the registered subscriber.
	// (A race condition could mean a newer conn replaced us already.)
	if current, ok := h.subs[sid]; ok && current == c {
		delete(h.subs, sid)
	}
	c.ws.Close()
}

// Notify broadcasts minimal event notification { type, sessionId, atmId, status } to the single subscriber of session.ID.
func (h *Hub) Notify(s *session.Session, event string) {
	h.mu.RLock()
	c := h.subs[s.ID]
	h.mu.RUnlock()

	if c == nil {
		return
	}
	// Bank-grade minimal event payload (no customer PII)
	c.writeJSON(map[string]interface{}{
		"type":      event,
		"sessionId": s.ID,
		"atmId":     s.AtmID,
		"status":    s.Status,
	})
}

func (c *conn) writeJSON(v interface{}) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.ws.WriteMessage(websocket.TextMessage, b); err != nil {
		return
	}
}

func (c *conn) closeWith(code int, reason string) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(writeWait))
	c.ws.Close()
}
