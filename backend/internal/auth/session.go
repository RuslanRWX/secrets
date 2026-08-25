// Package auth handles session tokens, API tokens and permission checks.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalidSession is returned for any unusable session token.
var ErrInvalidSession = errors.New("invalid or expired session")

// Sessions issues and verifies the JWTs used by the web UI.
type Sessions struct {
	secret []byte
	ttl    time.Duration
}

// NewSessions builds a session issuer.
func NewSessions(secret string, ttl time.Duration) *Sessions {
	return &Sessions{secret: []byte(secret), ttl: ttl}
}

// Claims is the payload carried by a session token.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
}

// Issue mints a session token for a user.
func (s *Sessions) Issue(userID uuid.UUID, username string, admin bool) (string, time.Time, error) {
	expiry := time.Now().Add(s.ttl)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiry),
			Issuer:    "secrets",
		},
		Username: username,
		Admin:    admin,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign session: %w", err)
	}

	return signed, expiry, nil
}

// Verify parses a session token and returns the user it belongs to.
func (s *Sessions) Verify(token string) (uuid.UUID, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}

		return s.secret, nil
	}, jwt.WithIssuer("secrets"), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return uuid.Nil, ErrInvalidSession
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return uuid.Nil, ErrInvalidSession
	}

	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, ErrInvalidSession
	}

	return id, nil
}
