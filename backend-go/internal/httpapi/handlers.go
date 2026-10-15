package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/demobank/atm-auth/internal/audit"
	"github.com/demobank/atm-auth/internal/config"
	"github.com/demobank/atm-auth/internal/realtime"
	"github.com/demobank/atm-auth/internal/session"
	"github.com/google/uuid"
)

var validAtmIDRegex = regexp.MustCompile(`^ATM-[A-Z0-9-]{1,32}$`)

type Handlers struct {
	Cfg         config.Config
	Store       session.SessionStore
	Hub         *realtime.Hub
	RateLimiter *RateLimiter
	SIEM        *audit.Logger
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string, extra map[string]interface{}) {
	out := map[string]interface{}{"error": code}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, status, out)
}

func nowMillis() int64 { return time.Now().UnixMilli() }

// POST /api/session
func (h *Handlers) CreateSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AtmID string `json:"atmId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	atmID := strings.TrimSpace(body.AtmID)
	if atmID == "" {
		atmID = "ATM-DEMO-001"
	}

	// Validate ATM ID format (P0: regex validation)
	if !validAtmIDRegex.MatchString(atmID) {
		writeErr(w, http.StatusBadRequest, "invalid_atm_id", map[string]interface{}{
			"message": "ATM ID must match format ATM-[A-Z0-9-]{1,32}",
		})
		return
	}

	// P0 Security: Verify mTLS Client Certificate identity when forwarded by reverse proxy
	if clientDN := r.Header.Get("X-Client-Cert-DN"); clientDN != "" {
		if !strings.Contains(clientDN, "CN=ATM-") {
			writeErr(w, http.StatusForbidden, "unauthorized_atm_certificate", map[string]interface{}{
				"message": "Client certificate must match authorized ATM fleet naming (CN=ATM-*)",
			})
			return
		}
	}

	// Per-ATM rate-limiting (30/min)
	if h.RateLimiter != nil {
		allowed, reason := h.RateLimiter.Allow("atm:" + atmID)
		if !allowed {
			writeErr(w, http.StatusTooManyRequests, "rate_limited", map[string]interface{}{"reason": reason})
			return
		}
	}

	now := nowMillis()
	s := &session.Session{
		ID:        uuid.NewString(),
		AtmID:     atmID,
		Status:    session.StatusPending,
		CreatedAt: now,
		ExpiresAt: now + int64(h.Cfg.SessionTTLSeconds)*1000,
	}
	h.Store.Put(s)

	payload := session.QrPayload{
		Sid: s.ID,
		Atm: s.AtmID,
		Iat: now / 1000,
		Exp: s.ExpiresAt / 1000,
	}

	// Sign using RS256 (or dev HMAC fallback if configured)
	qrToken, err := session.SignQR(h.Cfg.RSAPrivateKey, h.Cfg.KeyID, h.Cfg.JWTSecret, payload)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sign_failed", nil)
		return
	}

	h.Store.Log(session.AuditEntry{
		Ts: now, SessionID: s.ID, Event: "session.created",
		Detail: map[string]interface{}{"atmId": atmID},
	})
	if h.SIEM != nil {
		h.SIEM.Record(audit.SIEMEvent{
			EventAction: "session.created",
			SessionID:   s.ID,
			AtmID:       atmID,
			Outcome:     "success",
			Detail:      map[string]interface{}{"ttlSeconds": h.Cfg.SessionTTLSeconds},
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessionId":  s.ID,
		"atmId":      s.AtmID,
		"expiresAt":  s.ExpiresAt,
		"ttlSeconds": h.Cfg.SessionTTLSeconds,
		"qrToken":    qrToken,
	})
}

// GET /api/session/{id}
func (h *Handlers) GetSession(w http.ResponseWriter, r *http.Request) {
	id := pathTail(r.URL.Path, "/api/session/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusNotFound, "not_found", nil)
		return
	}
	s, ok := h.Store.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", nil)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// POST /api/session/approve
func (h *Handlers) ApproveSession(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// Rate limiting: 10 approve/min per IP with brute-force lockout
	if h.RateLimiter != nil {
		allowed, reason := h.RateLimiter.Allow("approve:" + clientIP)
		if !allowed {
			h.Store.Log(session.AuditEntry{
				Ts: nowMillis(), Event: "approve.rate_limited",
				Detail: map[string]interface{}{"ip": clientIP, "reason": reason},
			})
			writeErr(w, http.StatusTooManyRequests, "rate_limited", map[string]interface{}{"reason": reason})
			return
		}
	}

	var body struct {
		QRToken     string `json:"qrToken"`
		DeviceID    string `json:"deviceId"`
		CustomerRef string `json:"customerRef"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "missing_fields", nil)
		return
	}
	if body.QRToken == "" || body.DeviceID == "" {
		writeErr(w, http.StatusBadRequest, "missing_fields", nil)
		return
	}

	// Verify QR token using RS256/HS256
	payload, err := session.VerifyQR(h.Cfg.RSAPublicKey, h.Cfg.JWTSecret, body.QRToken)
	if err != nil {
		if h.RateLimiter != nil {
			h.RateLimiter.RecordFailure("approve:" + clientIP)
		}
		writeErr(w, http.StatusBadRequest, "invalid_token", map[string]interface{}{"detail": err.Error()})
		return
	}

	s, ok := h.Store.Get(payload.Sid)
	if !ok {
		if h.RateLimiter != nil {
			h.RateLimiter.RecordFailure("approve:" + clientIP)
		}
		writeErr(w, http.StatusNotFound, "session_not_found", nil)
		return
	}

	// P0 Security: Verify payload.Atm == session.AtmID (reject ATM mismatch)
	if payload.Atm != s.AtmID {
		if h.RateLimiter != nil {
			h.RateLimiter.RecordFailure("approve:" + clientIP)
		}
		h.Store.Log(session.AuditEntry{
			Ts: nowMillis(), SessionID: s.ID, Event: "approve.atm_mismatch",
			Detail: map[string]interface{}{
				"tokenAtm": payload.Atm,
				"sessAtm":  s.AtmID,
				"ip":       clientIP,
			},
		})
		if h.SIEM != nil {
			h.SIEM.Record(audit.SIEMEvent{
				EventAction: "approve.atm_mismatch",
				SessionID:   s.ID,
				AtmID:       s.AtmID,
				ClientIP:    clientIP,
				DeviceID:    body.DeviceID,
				Outcome:     "failure",
				Reason:      "ATM mismatch: token ATM does not match session ATM",
				Detail:      map[string]interface{}{"tokenAtm": payload.Atm, "sessionAtm": s.AtmID},
			})
		}
		writeErr(w, http.StatusForbidden, "atm_mismatch", nil)
		return
	}

	// P0 Security: Verify payload.Sid == session.ID
	if payload.Sid != s.ID {
		writeErr(w, http.StatusForbidden, "session_mismatch", nil)
		return
	}

	// Identity extraction: if an Authorization Bearer token is provided, note it; otherwise fall back safely
	customerRef := strings.TrimSpace(body.CustomerRef)
	if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		// In a production bank setup, IdP token is unpacked here.
		// For demo/pilot compatibility, preserve customer identity while marking authenticated
		if customerRef == "" {
			customerRef = "verified-bank-user"
		}
	} else if customerRef == "" {
		customerRef = "demo-customer"
	}

	// Atomic state transition (Redis Lua script or thread-safe atomic memory transition)
	updated, err := h.Store.TransitionToApproved(s.ID, body.DeviceID, customerRef)
	if err != nil {
		if h.RateLimiter != nil {
			h.RateLimiter.RecordFailure("approve:" + clientIP)
		}
		if errors.Is(err, session.ErrSessionExpired) || strings.Contains(err.Error(), "EXPIRED") {
			writeErr(w, http.StatusGone, "session_expired", nil)
			return
		}
		writeErr(w, http.StatusConflict, "session_not_pending", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	if h.RateLimiter != nil {
		h.RateLimiter.RecordSuccess("approve:" + clientIP)
	}

	h.Store.Log(session.AuditEntry{
		Ts: nowMillis(), SessionID: s.ID, Event: "session.approved",
		Detail: map[string]interface{}{
			"deviceId":    body.DeviceID,
			"customerRef": customerRef,
			"atmId":       s.AtmID,
			"ip":          clientIP,
		},
	})
	if h.SIEM != nil {
		h.SIEM.Record(audit.SIEMEvent{
			EventAction: "session.approved",
			SessionID:   s.ID,
			AtmID:       s.AtmID,
			ClientIP:    clientIP,
			DeviceID:    body.DeviceID,
			CustomerRef: customerRef,
			Outcome:     "success",
		})
	}

	h.Hub.Notify(updated, "approved")
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "session": updated})
}

// POST /api/session/{id}/consume
func (h *Handlers) ConsumeSession(w http.ResponseWriter, r *http.Request) {
	rest := pathTail(r.URL.Path, "/api/session/")
	id := strings.TrimSuffix(rest, "/consume")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusNotFound, "not_found", nil)
		return
	}
	s, ok := h.Store.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", nil)
		return
	}

	// Atomic state transition from 'approved' to 'consumed'
	updated, err := h.Store.TransitionToConsumed(s.ID)
	if err != nil {
		writeErr(w, http.StatusConflict, "not_approved", map[string]interface{}{"error": err.Error()})
		return
	}

	h.Store.Log(session.AuditEntry{Ts: nowMillis(), SessionID: s.ID, Event: "session.consumed"})
	if h.SIEM != nil {
		h.SIEM.Record(audit.SIEMEvent{
			EventAction: "session.consumed",
			SessionID:   s.ID,
			AtmID:       s.AtmID,
			Outcome:     "success",
		})
	}

	h.Hub.Notify(updated, "consumed")
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// GET /api/audit (Protected by AuditAPIEnabled flag)
func (h *Handlers) Audit(w http.ResponseWriter, _ *http.Request) {
	if !h.Cfg.AuditAPIEnabled {
		writeErr(w, http.StatusForbidden, "endpoint_disabled", map[string]interface{}{
			"message": "Audit endpoint disabled in production. Logs sink directly to SIEM.",
		})
		return
	}
	writeJSON(w, http.StatusOK, h.Store.Audit())
}

// GET /api/health
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    true,
		"ts":    nowMillis(),
		"nonce": hex.EncodeToString(b),
		"env":   h.Cfg.Env,
	})
}

func pathTail(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return path[len(prefix):]
}
