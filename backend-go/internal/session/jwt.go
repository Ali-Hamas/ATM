package session

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	IssuerBankAuthServer = "bank-auth-server"
	AudienceATMAuth      = "atm-auth"
	MaxClockSkewSeconds  = 30
)

var (
	ErrTokenExpired      = errors.New("token expired")
	ErrInvalidIssuer     = errors.New("invalid token issuer")
	ErrInvalidAudience   = errors.New("invalid token audience")
	ErrInvalidSignature  = errors.New("invalid token signature")
	ErrForbiddenMethod   = errors.New("forbidden algorithm or method")
	ErrTokenIssuedFuture = errors.New("token issued in the future (exceeds clock skew)")
	ErrMissingClaims     = errors.New("token missing required claims")
)

// SignQR signs the QR payload using RS256 if RSA private key is configured,
// or fallback HS256 for local dev testing.
// Embeds strict enterprise claims: iss, aud, exp, iat, kid.
func SignQR(rsaPriv *rsa.PrivateKey, kid, secret string, p QrPayload) (string, error) {
	claims := jwt.MapClaims{
		"iss": IssuerBankAuthServer,
		"aud": AudienceATMAuth,
		"sid": p.Sid,
		"atm": p.Atm,
		"iat": p.Iat,
		"exp": p.Exp,
	}

	if rsaPriv != nil {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if kid != "" {
			tok.Header["kid"] = kid
		}
		return tok.SignedString(rsaPriv)
	}

	if secret != "" {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return tok.SignedString([]byte(secret))
	}

	return "", errors.New("no signing key available (neither RSA private key nor HMAC secret)")
}

// VerifyQR parses the token with strict cryptographic enforcement:
// - Strictly enforces WithIssuer("bank-auth-server")
// - Strictly enforces WithAudience("atm-auth")
// - Enforces valid methods (RS256, or HS256 if secret provided)
// - Validates iat not in future (clock skew <= 30s)
// - Validates exp expiry (clock skew <= 30s)
// - No lenient fallback: any malformed, unsigned, or mismatched token is strictly rejected.
func VerifyQR(rsaPub *rsa.PublicKey, secret, tokenString string) (QrPayload, error) {
	validMethods := []string{"RS256"}
	if secret != "" {
		validMethods = append(validMethods, "HS256")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
		jwt.WithIssuer(IssuerBankAuthServer),
		jwt.WithAudience(AudienceATMAuth),
	)

	parsed, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			if rsaPub == nil {
				return nil, errors.New("token signed with RS256 but server has no RSA public key configured")
			}
			return rsaPub, nil
		case *jwt.SigningMethodHMAC:
			if secret == "" {
				return nil, errors.New("token signed with HS256 but server has no HMAC secret configured")
			}
			return []byte(secret), nil
		default:
			return nil, fmt.Errorf("%w: %v", ErrForbiddenMethod, t.Header["alg"])
		}
	})

	if err != nil {
		return QrPayload{}, fmt.Errorf("jwt validation failed: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return QrPayload{}, ErrMissingClaims
	}

	out := QrPayload{}
	if v, ok := claims["sid"].(string); ok {
		out.Sid = v
	}
	if v, ok := claims["atm"].(string); ok {
		out.Atm = v
	}
	if v, ok := claims["iat"].(float64); ok {
		out.Iat = int64(v)
	}
	if v, ok := claims["exp"].(float64); ok {
		out.Exp = int64(v)
	}

	if out.Sid == "" || out.Atm == "" {
		return QrPayload{}, ErrMissingClaims
	}

	nowSec := time.Now().Unix()

	// Reject tokens issued unreasonably in the future
	if out.Iat > (nowSec + MaxClockSkewSeconds) {
		return QrPayload{}, ErrTokenIssuedFuture
	}

	// Reject expired tokens
	if out.Exp > 0 && nowSec > (out.Exp+MaxClockSkewSeconds) {
		return QrPayload{}, ErrTokenExpired
	}

	return out, nil
}
