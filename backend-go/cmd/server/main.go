package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/demobank/atm-auth/internal/audit"
	"github.com/demobank/atm-auth/internal/config"
	"github.com/demobank/atm-auth/internal/httpapi"
	"github.com/demobank/atm-auth/internal/realtime"
	"github.com/demobank/atm-auth/internal/session"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	// In development/test mode, if no RSA key was loaded from environment/file,
	// generate an ephemeral 2048-bit RSA key pair automatically for bank-grade crypto
	if cfg.RSAPrivateKey == nil && cfg.Env != "prod" && cfg.Env != "production" {
		log.Println("[security] No RSA key provided; generating ephemeral 2048-bit RSA key pair for bank-grade RS256 token signing...")
		ephemeralKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("failed to generate ephemeral RSA key: %v", err)
		}
		cfg.RSAPrivateKey = ephemeralKey
		cfg.RSAPublicKey = &ephemeralKey.PublicKey
	}

	// ── 1. Enterprise Session Store (Redis vs In-Memory Fallback) ─────────────
	var store session.SessionStore
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			// Try as raw host:port address
			opt = &redis.Options{Addr: cfg.RedisURL}
		}
		redisClient := redis.NewClient(opt)
		redisStore, err := session.NewRedisStore(redisClient, cfg.SessionTTLSeconds)
		if err != nil {
			log.Printf("[persistence] Warning: Redis at %s unreachable (%v). Falling back to in-memory store.", cfg.RedisURL, err)
			store = session.NewStore()
		} else {
			log.Printf("[persistence] Connected to distributed Redis at %s with atomic Lua state transitions.", opt.Addr)
			store = redisStore
		}
	} else {
		log.Println("[persistence] No REDIS_URL provided; using thread-safe in-memory session store.")
		store = session.NewStore()
	}

	// ── 2. Enterprise SIEM & Immutable Audit Logger ───────────────────────────
	siemLogger, err := audit.NewLogger(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("audit logger error: %v", err)
	}
	defer siemLogger.Close()

	hub := realtime.NewHub(func(sid string) bool {
		sess, ok := store.Get(sid)
		return ok && sess != nil && sess.Status != session.StatusExpired
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.RunSweeper(ctx)

	// Rate limiter: 60 requests/min, 5 consecutive failures -> 5-min lockout
	rateLimiter := httpapi.NewRateLimiter(60, 5, 5*time.Minute)

	handlers := &httpapi.Handlers{
		Cfg:         cfg,
		Store:       store,
		Hub:         hub,
		RateLimiter: rateLimiter,
		SIEM:        siemLogger,
	}
	router := httpapi.NewRouter(handlers, hub)

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("[server] auth middleware listening on %s (env=%s, alg=RS256)", addr, cfg.Env)
		log.Printf("[server] ws endpoint  ws://localhost%s/ws?sid=<sessionId>", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	log.Println("shutdown signal received, draining…")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	log.Println("bye")
}
