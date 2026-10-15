package httpapi

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type clientLimit struct {
	attempts     int
	windowStart  time.Time
	failedCount  int
	lockedUntil  time.Time
}

type RateLimiter struct {
	mu           sync.Mutex
	clients      map[string]*clientLimit
	maxPerMinute int
	maxFails     int
	lockoutDur   time.Duration
}

func NewRateLimiter(maxPerMinute, maxFails int, lockoutDur time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients:      make(map[string]*clientLimit),
		maxPerMinute: maxPerMinute,
		maxFails:     maxFails,
		lockoutDur:   lockoutDur,
	}

	// Background cleanup of stale entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) Allow(key string) (bool, string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cl, exists := rl.clients[key]
	if !exists {
		rl.clients[key] = &clientLimit{
			attempts:    1,
			windowStart: now,
		}
		return true, ""
	}

	if now.Before(cl.lockedUntil) {
		return false, "locked"
	}

	// Reset window if > 1 minute
	if now.Sub(cl.windowStart) > time.Minute {
		cl.attempts = 1
		cl.windowStart = now
		return true, ""
	}

	if cl.attempts >= rl.maxPerMinute {
		return false, "rate_limited"
	}

	cl.attempts++
	return true, ""
}

func (rl *RateLimiter) RecordFailure(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cl, exists := rl.clients[key]
	if !exists {
		return
	}
	cl.failedCount++
	if cl.failedCount >= rl.maxFails {
		cl.lockedUntil = time.Now().Add(rl.lockoutDur)
		cl.failedCount = 0
	}
}

func (rl *RateLimiter) RecordSuccess(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if cl, exists := rl.clients[key]; exists {
		cl.failedCount = 0
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for k, cl := range rl.clients {
		if now.Sub(cl.windowStart) > 10*time.Minute && now.After(cl.lockedUntil) {
			delete(rl.clients, k)
		}
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// r.RemoteAddr is host:port
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
