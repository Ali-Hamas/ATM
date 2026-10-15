package session_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/demobank/atm-auth/internal/session"
)

func TestRS256SignAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	payload := session.QrPayload{
		Sid: "sess-12345",
		Atm: "ATM-DEMO-001",
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(60 * time.Second).Unix(),
	}

	token, err := session.SignQR(key, "test-kid", "", payload)
	if err != nil {
		t.Fatalf("SignQR failed: %v", err)
	}

	verified, err := session.VerifyQR(&key.PublicKey, "", token)
	if err != nil {
		t.Fatalf("VerifyQR failed: %v", err)
	}

	if verified.Sid != payload.Sid {
		t.Errorf("expected Sid %s, got %s", payload.Sid, verified.Sid)
	}
	if verified.Atm != payload.Atm {
		t.Errorf("expected Atm %s, got %s", payload.Atm, verified.Atm)
	}
}

func TestVerifyQRExpired(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	payload := session.QrPayload{
		Sid: "sess-expired",
		Atm: "ATM-DEMO-001",
		Iat: time.Now().Add(-120 * time.Second).Unix(),
		Exp: time.Now().Add(-60 * time.Second).Unix(),
	}

	token, err := session.SignQR(key, "test-kid", "", payload)
	if err != nil {
		t.Fatalf("SignQR failed: %v", err)
	}

	_, err = session.VerifyQR(&key.PublicKey, "", token)
	if err == nil {
		t.Fatal("expected expired token error, got nil")
	}
}
