package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TokenPrefixLabel is the fixed marker at the front of every API token, which
// makes leaked tokens easy to spot in logs and secret scanners.
const TokenPrefixLabel = "sks"

// ErrMalformedToken is returned when a bearer value is not shaped like an API token.
var ErrMalformedToken = errors.New("malformed api token")

// MintedToken is the one-time result of issuing an API token.
type MintedToken struct {
	// Plaintext is shown to the caller exactly once and never stored.
	Plaintext string
	// Prefix identifies the token row without revealing the secret half.
	Prefix string
	// Hash is what goes in the database.
	Hash []byte
}

// MintToken generates a new API token of the form sks_<prefix>_<secret>.
func MintToken() (*MintedToken, error) {
	prefixBytes := make([]byte, 6)
	if _, err := rand.Read(prefixBytes); err != nil {
		return nil, fmt.Errorf("generate token prefix: %w", err)
	}

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("generate token secret: %w", err)
	}

	prefix := hex.EncodeToString(prefixBytes)
	plaintext := fmt.Sprintf("%s_%s_%s", TokenPrefixLabel, prefix,
		base64.RawURLEncoding.EncodeToString(secretBytes))
	hash := sha256.Sum256([]byte(plaintext))

	return &MintedToken{Plaintext: plaintext, Prefix: prefix, Hash: hash[:]}, nil
}

// SplitToken extracts the lookup prefix from a presented token. The secret half
// is base64url, whose alphabet includes "_", so only the first two separators
// may be treated as delimiters.
func SplitToken(presented string) (prefix string, err error) {
	parts := strings.SplitN(presented, "_", 3)
	if len(parts) != 3 || parts[0] != TokenPrefixLabel || parts[1] == "" || parts[2] == "" {
		return "", ErrMalformedToken
	}

	return parts[1], nil
}

// HashToken hashes a presented token for constant-time comparison with the stored hash.
func HashToken(presented string) []byte {
	sum := sha256.Sum256([]byte(presented))

	return sum[:]
}
