package httpapi_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/demobank/atm-auth/internal/config"
	"github.com/demobank/atm-auth/internal/httpapi"
	"github.com/demobank/atm-auth/internal/realtime"
	"github.com/demobank/atm-auth/internal/session"
)

func setupTestServer(t *testing.T) (*httptest.Server, *httpapi.Handlers, *session.Store, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	cfg := config.Config{
		Port:              4000,
		Env:               "test",
		SessionTTLSeconds: 60,
		AllowedOrigins:    []string{"http://localhost:4000"},
		AuditAPIEnabled:   true,
		RSAPrivateKey:     key,
		RSAPublicKey:      &key.PublicKey,
		KeyID:             "test-key-id",
	}

	store := session.NewStore()
	hub := realtime.NewHub()
	limiter := httpapi.NewRateLimiter(60, 5, 5*time.Minute)

	handlers := &httpapi.Handlers{
		Cfg:         cfg,
		Store:       store,
		Hub:         hub,
		RateLimiter: limiter,
	}

	router := httpapi.NewRouter(handlers, hub)
	ts := httptest.NewServer(router)
	return ts, handlers, store, key
}

func TestCreateSessionValidATM(t *testing.T) {
	ts, _, _, _ := setupTestServer(t)
	defer ts.Close()

	body := []byte(`{"atmId":"ATM-LONDON-01"}`)
	res, err := http.Post(ts.URL+"/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("POST /api/session failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if data["atmId"] != "ATM-LONDON-01" {
		t.Errorf("expected ATM-LONDON-01, got %v", data["atmId"])
	}
	if data["qrToken"] == "" || data["sessionId"] == "" {
		t.Errorf("missing qrToken or sessionId: %v", data)
	}
}

func TestCreateSessionInvalidATMFormat(t *testing.T) {
	ts, _, _, _ := setupTestServer(t)
	defer ts.Close()

	// Invalid format (does not match ATM-[A-Z0-9-]{1,32})
	body := []byte(`{"atmId":"invalid_atm_lowercase!"}`)
	res, err := http.Post(ts.URL+"/api/session", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("POST /api/session failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ATM format, got %d", res.StatusCode)
	}
}

func TestApproveSessionSuccess(t *testing.T) {
	ts, _, _, _ := setupTestServer(t)
	defer ts.Close()

	// 1. Create session
	createRes, err := http.Post(ts.URL+"/api/session", "application/json", bytes.NewBuffer([]byte(`{"atmId":"ATM-MAIN-001"}`)))
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}
	var created map[string]interface{}
	_ = json.NewDecoder(createRes.Body).Decode(&created)
	createRes.Body.Close()

	qrToken := created["qrToken"].(string)

	// 2. Approve session
	approveBody, _ := json.Marshal(map[string]string{
		"qrToken":     qrToken,
		"deviceId":    "test-phone-device",
		"customerRef": "John Doe",
	})
	appRes, err := http.Post(ts.URL+"/api/session/approve", "application/json", bytes.NewBuffer(approveBody))
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	defer appRes.Body.Close()

	if appRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", appRes.StatusCode)
	}
}

func TestApproveSessionAtmMismatchRejected(t *testing.T) {
	ts, _, store, key := setupTestServer(t)
	defer ts.Close()

	// Create session for ATM-A
	now := time.Now().UnixMilli()
	sess := &session.Session{
		ID:        "session-xyz",
		AtmID:     "ATM-ACTUAL-001",
		Status:    session.StatusPending,
		CreatedAt: now,
		ExpiresAt: now + 60000,
	}
	store.Put(sess)

	// Craft QR payload with different ATM (ATM-FORGED-002)
	payload := session.QrPayload{
		Sid: sess.ID,
		Atm: "ATM-FORGED-002",
		Iat: now / 1000,
		Exp: (now + 60000) / 1000,
	}
	forgedToken, err := session.SignQR(key, "test-key-id", "", payload)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	approveBody, _ := json.Marshal(map[string]string{
		"qrToken":     forgedToken,
		"deviceId":    "test-phone-device",
		"customerRef": "Attacker",
	})
	res, err := http.Post(ts.URL+"/api/session/approve", "application/json", bytes.NewBuffer(approveBody))
	if err != nil {
		t.Fatalf("POST /api/session/approve failed: %v", err)
	}
	defer res.Body.Close()

	// Must be rejected with 403 Forbidden due to atm_mismatch check
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on ATM mismatch, got %d", res.StatusCode)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	ts, _, _, _ := setupTestServer(t)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health failed: %v", err)
	}
	defer res.Body.Close()

	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing X-Frame-Options: DENY")
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing X-Content-Type-Options: nosniff")
	}
	if res.Header.Get("Strict-Transport-Security") == "" {
		t.Errorf("missing Strict-Transport-Security")
	}
	if res.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("missing Content-Security-Policy")
	}
}
