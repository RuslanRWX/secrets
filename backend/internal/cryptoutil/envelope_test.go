package cryptoutil

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	k, err := NewKeyring("a-sufficiently-long-master-key")
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}

	plaintext := []byte("hunter2-but-longer")

	wrapped, ciphertext, err := k.Seal(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}

	got, err := k.Open(wrapped, ciphertext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestSealUsesFreshDataKeyEachTime(t *testing.T) {
	k, _ := NewKeyring("a-sufficiently-long-master-key")

	wrapped1, cipher1, _ := k.Seal([]byte("same value"))
	wrapped2, cipher2, _ := k.Seal([]byte("same value"))

	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("two seals produced the same wrapped data key")
	}
	if bytes.Equal(cipher1, cipher2) {
		t.Fatal("two seals of the same value produced identical ciphertext")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	good, _ := NewKeyring("a-sufficiently-long-master-key")
	bad, _ := NewKeyring("a-completely-different-master-key")

	wrapped, ciphertext, _ := good.Seal([]byte("top secret"))

	if _, err := bad.Open(wrapped, ciphertext); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("expected ErrWrongKey, got %v", err)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	k, _ := NewKeyring("a-sufficiently-long-master-key")

	wrapped, ciphertext, _ := k.Seal([]byte("top secret"))
	ciphertext[len(ciphertext)-1] ^= 0xff

	if _, err := k.Open(wrapped, ciphertext); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestKeyCheckDetectsWrongMasterKey(t *testing.T) {
	good, _ := NewKeyring("a-sufficiently-long-master-key")
	bad, _ := NewKeyring("a-completely-different-master-key")

	check, err := good.NewKeyCheck()
	if err != nil {
		t.Fatalf("new key check: %v", err)
	}

	if err := good.VerifyKeyCheck(check); err != nil {
		t.Fatalf("correct key rejected: %v", err)
	}
	if err := bad.VerifyKeyCheck(check); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("expected ErrWrongKey, got %v", err)
	}
	if err := good.VerifyKeyCheck(nil); err != nil {
		t.Fatalf("empty check should pass: %v", err)
	}
}

func TestShortMasterKeyRejected(t *testing.T) {
	if _, err := NewKeyring("short"); err == nil {
		t.Fatal("expected a short master key to be rejected")
	}
}

func TestKeyIDIsStableAndKeySpecific(t *testing.T) {
	a, _ := NewKeyring("a-sufficiently-long-master-key")
	b, _ := NewKeyring("a-sufficiently-long-master-key")
	c, _ := NewKeyring("a-completely-different-master-key")

	if a.KeyID() != b.KeyID() {
		t.Fatal("same master key produced different key ids")
	}
	if a.KeyID() == c.KeyID() {
		t.Fatal("different master keys produced the same key id")
	}
}
