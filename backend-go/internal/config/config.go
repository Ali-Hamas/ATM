package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port              int
	Env               string
	SessionTTLSeconds int
	AllowedOrigins    []string
	AuditAPIEnabled   bool

	// Cryptographic keys (RS256)
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
	KeyID         string

	// Enterprise Persistence & Audit Database
	RedisURL    string
	DatabaseURL string

	// Legacy HMAC secret (optional fallback for dev environments)
	JWTSecret string

	// Strict Security & Fleet Configuration
	RequireMTLS      bool
	ATMAllowlist     []string
	RedisRequired    bool
	DatabaseRequired bool
}

func Load() (Config, error) {
	env := envStr("ENV", "development")
	isProd := strings.EqualFold(env, "prod") || strings.EqualFold(env, "production")

	cfg := Config{
		Port:              envInt("PORT", 4000),
		Env:               env,
		SessionTTLSeconds: envInt("SESSION_TTL_SECONDS", 60),
		AllowedOrigins:    parseOrigins(envStr("ALLOWED_ORIGINS", "http://localhost:4000,http://127.0.0.1:4000")),
		AuditAPIEnabled:   envBool("ENABLE_AUDIT_API", !isProd),
		KeyID:             envStr("JWT_KID", "bank-atm-key-1"),
		RedisURL:          envStr("REDIS_URL", os.Getenv("REDIS_ADDR")),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RequireMTLS:       envBool("REQUIRE_MTLS", isProd),
		ATMAllowlist:      parseOrigins(envStr("ATM_ALLOWLIST", "ATM-DEMO-001,ATM-001,ATM-LONDON-01,ATM-MAIN-001")),
		RedisRequired:     envBool("REDIS_REQUIRED", isProd),
		DatabaseRequired:  envBool("DATABASE_REQUIRED", isProd),
	}

	// 1. Try loading RSA Private Key (file path or inline PEM env)
	privKeyPEM := os.Getenv("RSA_PRIVATE_KEY")
	if privKeyPath := os.Getenv("RSA_PRIVATE_KEY_FILE"); privKeyPath != "" {
		b, err := os.ReadFile(privKeyPath)
		if err != nil {
			return cfg, fmt.Errorf("failed to read RSA_PRIVATE_KEY_FILE: %w", err)
		}
		privKeyPEM = string(b)
	}

	if privKeyPEM != "" {
		priv, err := parseRSAPrivateKey(privKeyPEM)
		if err != nil {
			return cfg, fmt.Errorf("invalid RSA private key: %w", err)
		}
		cfg.RSAPrivateKey = priv
		cfg.RSAPublicKey = &priv.PublicKey
	}

	// 2. Try loading RSA Public Key if private is not provided or explicitly overridden
	pubKeyPEM := os.Getenv("RSA_PUBLIC_KEY")
	if pubKeyPath := os.Getenv("RSA_PUBLIC_KEY_FILE"); pubKeyPath != "" {
		b, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return cfg, fmt.Errorf("failed to read RSA_PUBLIC_KEY_FILE: %w", err)
		}
		pubKeyPEM = string(b)
	}
	if pubKeyPEM != "" && cfg.RSAPublicKey == nil {
		pub, err := parseRSAPublicKey(pubKeyPEM)
		if err != nil {
			return cfg, fmt.Errorf("invalid RSA public key: %w", err)
		}
		cfg.RSAPublicKey = pub
	}

	// 3. Fallback secret handling
	cfg.JWTSecret = os.Getenv("JWT_SECRET")

	// In production, we MUST have RSA keys and MUST NOT have dev/HMAC secrets
	if isProd {
		if cfg.RSAPrivateKey == nil {
			return cfg, errors.New("FATAL: Production environment requires RSA_PRIVATE_KEY or RSA_PRIVATE_KEY_FILE for RS256 token signing")
		}
		if cfg.JWTSecret != "" {
			return cfg, errors.New("FATAL: Symmetric JWT_SECRET is strictly forbidden in production; RS256 with RSA keys is mandatory")
		}
	}

	return cfg, nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing RSA private key")
	}

	// PKCS1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// PKCS8
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key (tried PKCS1 & PKCS8): %w", err)
	}
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key parsed from PKCS8 is not an RSA private key")
	}
	return rsaKey, nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing RSA public key")
	}

	// PKIX
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if pub, ok := pubInterface.(*rsa.PublicKey); ok {
			return pub, nil
		}
	}

	// PKCS1
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	return nil, errors.New("unable to parse public key (tried PKIX & PKCS1)")
}

func parseOrigins(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}
