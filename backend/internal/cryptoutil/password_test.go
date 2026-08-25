package cryptoutil

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := VerifyPassword(hash, "correct horse battery staple")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("correct password was rejected")
	}

	ok, err = VerifyPassword(hash, "wrong password entirely")
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if ok {
		t.Fatal("wrong password was accepted")
	}
}

func TestPasswordHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same password")
	b, _ := HashPassword("same password")

	if a == b {
		t.Fatal("identical passwords produced identical hashes")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, encoded := range []string{"", "plaintext", "$bcrypt$v=19$m=1,t=1,p=1$aaaa$bbbb"} {
		if _, err := VerifyPassword(encoded, "whatever"); err == nil {
			t.Fatalf("expected an error for hash %q", encoded)
		}
	}
}
