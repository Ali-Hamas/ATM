package session_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/demobank/atm-auth/internal/session"
	"github.com/golang-jwt/jwt/v5"
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

// TestJWTStrictMatrix rigorously tests CODE-001 & CODE-002:
// Validates that any deviation in iss, aud, future iat, or alg is strictly rejected.
func TestJWTStrictMatrix(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	now := time.Now().Unix()

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		signKey   interface{}
		method    jwt.SigningMethod
		shouldErr bool
	}{
		{
			name: "Valid strict RS256 token",
			claims: jwt.MapClaims{
				"iss": session.IssuerBankAuthServer,
				"aud": session.AudienceATMAuth,
				"sid": "sess-valid",
				"atm": "ATM-TEST-001",
				"iat": now,
				"exp": now + 60,
			},
			signKey:   key,
			method:    jwt.SigningMethodRS256,
			shouldErr: false,
		},
		{
			name: "Wrong Issuer (must fail without fallback)",
			claims: jwt.MapClaims{
				"iss": "rogue-issuer",
				"aud": session.AudienceATMAuth,
				"sid": "sess-wrong-iss",
				"atm": "ATM-TEST-001",
				"iat": now,
				"exp": now + 60,
			},
			signKey:   key,
			method:    jwt.SigningMethodRS256,
			shouldErr: true,
		},
		{
			name: "Wrong Audience (must fail without fallback)",
			claims: jwt.MapClaims{
				"iss": session.IssuerBankAuthServer,
				"aud": "rogue-aud",
				"sid": "sess-wrong-aud",
				"atm": "ATM-TEST-001",
				"iat": now,
				"exp": now + 60,
			},
			signKey:   key,
			method:    jwt.SigningMethodRS256,
			shouldErr: true,
		},
		{
			name: "Missing Issuer (must fail without fallback)",
			claims: jwt.MapClaims{
				"aud": session.AudienceATMAuth,
				"sid": "sess-no-iss",
				"atm": "ATM-TEST-001",
				"iat": now,
				"exp": now + 60,
			},
			signKey:   key,
			method:    jwt.SigningMethodRS256,
			shouldErr: true,
		},
		{
			name: "Missing Audience (must fail without fallback)",
			claims: jwt.MapClaims{
				"iss": session.IssuerBankAuthServer,
				"sid": "sess-no-aud",
				"atm": "ATM-TEST-001",
				"iat": now,
				"exp": now + 60,
			},
			signKey:   key,
			method:    jwt.SigningMethodRS256,
			shouldErr: true,
		},
		{
			name: "Future iat beyond skew (must fail)",
			claims: jwt.MapClaims{
				"iss": session.IssuerBankAuthServer,
				"aud": session.AudienceATMAuth,
				"sid": "sess-future",
				"atm": "ATM-TEST-001",
				"iat": now + 120, // +2 min in future
				"exp": now + 300,
			},
			signKey:   key,
			method:    jwt.SigningMethodRS256,
			shouldErr: true,
		},
		{
			name: "alg=none (must fail)",
			claims: jwt.MapClaims{
				"iss": session.IssuerBankAuthServer,
				"aud": session.AudienceATMAuth,
				"sid": "sess-none",
				"atm": "ATM-TEST-001",
				"iat": now,
				"exp": now + 60,
			},
			signKey:   jwt.UnsafeAllowNoneSignatureType,
			method:    jwt.SigningMethodNone,
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(tc.method, tc.claims)
			signedStr, err := token.SignedString(tc.signKey)
			if err != nil && !tc.shouldErr {
				t.Fatalf("failed to sign token: %v", err)
			}

			_, err = session.VerifyQR(&key.PublicKey, "", signedStr)
			if tc.shouldErr && err == nil {
				t.Errorf("expected error for case '%s', but got nil", tc.name)
			} else if !tc.shouldErr && err != nil {
				t.Errorf("expected success for case '%s', but got error: %v", tc.name, err)
			}
		})
	}
}
