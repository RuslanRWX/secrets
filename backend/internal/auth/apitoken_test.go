package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestMintTokenShape(t *testing.T) {
	minted, err := MintToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if !strings.HasPrefix(minted.Plaintext, TokenPrefixLabel+"_") {
		t.Fatalf("token is missing its label: %q", minted.Plaintext)
	}

	prefix, err := SplitToken(minted.Plaintext)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if prefix != minted.Prefix {
		t.Fatalf("split prefix %q does not match minted prefix %q", prefix, minted.Prefix)
	}
	if !bytes.Equal(HashToken(minted.Plaintext), minted.Hash) {
		t.Fatal("hash of the plaintext does not match the stored hash")
	}
}

func TestMintedTokensAreUnique(t *testing.T) {
	a, _ := MintToken()
	b, _ := MintToken()

	if a.Plaintext == b.Plaintext || a.Prefix == b.Prefix {
		t.Fatal("two minted tokens collided")
	}
}

func TestSplitTokenRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "nope", "sks_only-two-parts", "xxx_aaa_bbb", "sks__bbb"} {
		if _, err := SplitToken(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

// The secret half is base64url, whose alphabet contains "_". Splitting on every
// separator instead of the first two made authentication fail at random.
func TestSplitTokenHandlesUnderscoreInSecret(t *testing.T) {
	prefix, err := SplitToken("sks_abc123_ZmFrZV9zZWNyZXRfd2l0aF91bmRlcnNjb3Jlcw")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if prefix != "abc123" {
		t.Fatalf("got prefix %q want %q", prefix, "abc123")
	}
}

func TestMintedTokensAlwaysSplitBack(t *testing.T) {
	for i := 0; i < 500; i++ {
		minted, err := MintToken()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		prefix, err := SplitToken(minted.Plaintext)
		if err != nil {
			t.Fatalf("split %q: %v", minted.Plaintext, err)
		}
		if prefix != minted.Prefix {
			t.Fatalf("prefix mismatch for %q", minted.Plaintext)
		}
	}
}
