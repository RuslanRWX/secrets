// Package cryptoutil implements envelope encryption for secret values.
//
// The operator supplies a master key. From it we derive a key-encryption key
// (KEK) via HKDF-SHA256. Every secret value gets its own random 256-bit data
// encryption key (DEK); the value is sealed with the DEK and the DEK is sealed
// with the KEK. Only the wrapped DEK and the ciphertext are stored, so rotating
// the master key means re-wrapping DEKs rather than re-encrypting every value.
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	keySize   = 32
	nonceSize = 12
	// hkdfInfo separates the KEK from any other key derived from the same master key.
	hkdfInfo = "secrets/kek/v1"
	// checkPlaintext is sealed at install time so a later start with the wrong
	// master key is detected immediately instead of on first secret read.
	checkPlaintext = "secrets-master-key-check-v1"
)

// ErrWrongKey is returned when a ciphertext cannot be opened with the configured key.
var ErrWrongKey = errors.New("master key does not match the data in this database")

// Keyring holds the derived KEK and the identifier recorded alongside every ciphertext.
type Keyring struct {
	kek   []byte
	keyID string
}

// NewKeyring derives a key-encryption key from the operator-supplied master key.
// The master key must carry at least 16 bytes of material.
func NewKeyring(masterKey string) (*Keyring, error) {
	if len(masterKey) < 16 {
		return nil, errors.New("master key must be at least 16 characters")
	}

	kek := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(masterKey), nil, []byte(hkdfInfo)), kek); err != nil {
		return nil, fmt.Errorf("derive kek: %w", err)
	}

	// A short, non-reversible fingerprint of the KEK, used to tag ciphertexts so
	// that a value can be traced to the key that sealed it.
	sum := sha256.Sum256(kek)

	return &Keyring{kek: kek, keyID: hex.EncodeToString(sum[:4])}, nil
}

// KeyID identifies the active key-encryption key.
func (k *Keyring) KeyID() string { return k.keyID }

// Seal generates a fresh data key, encrypts plaintext with it, and returns the
// wrapped data key alongside the ciphertext.
func (k *Keyring) Seal(plaintext []byte) (wrappedDEK, ciphertext []byte, err error) {
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("generate data key: %w", err)
	}

	ciphertext, err = encrypt(dek, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt value: %w", err)
	}

	wrappedDEK, err = encrypt(k.kek, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap data key: %w", err)
	}

	return wrappedDEK, ciphertext, nil
}

// Open unwraps the data key and decrypts the ciphertext.
func (k *Keyring) Open(wrappedDEK, ciphertext []byte) ([]byte, error) {
	dek, err := decrypt(k.kek, wrappedDEK)
	if err != nil {
		return nil, ErrWrongKey
	}

	plaintext, err := decrypt(dek, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}

	return plaintext, nil
}

// NewKeyCheck seals a known constant so the key can be verified on later starts.
func (k *Keyring) NewKeyCheck() ([]byte, error) {
	return encrypt(k.kek, []byte(checkPlaintext))
}

// VerifyKeyCheck reports whether this keyring can open a check value written earlier.
func (k *Keyring) VerifyKeyCheck(check []byte) error {
	if len(check) == 0 {
		return nil // Nothing recorded yet (database predates the check, or not installed).
	}

	got, err := decrypt(k.kek, check)
	if err != nil || !hmac.Equal(got, []byte(checkPlaintext)) {
		return ErrWrongKey
	}

	return nil
}

// encrypt seals plaintext with AES-256-GCM, prefixing the random nonce.
func encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(blob) < nonceSize {
		return nil, errors.New("ciphertext is truncated")
	}

	return gcm.Open(nil, blob[:nonceSize], blob[nonceSize:], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	return cipher.NewGCM(block)
}
