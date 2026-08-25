package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionRoundTrip(t *testing.T) {
	s := NewSessions("a-sufficiently-long-jwt-secret", time.Hour)
	id := uuid.New()

	token, expiry, err := s.Issue(id, "alice", true)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !expiry.After(time.Now()) {
		t.Fatal("expiry is in the past")
	}

	got, err := s.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != id {
		t.Fatalf("got subject %s want %s", got, id)
	}
}

func TestVerifyRejectsForeignSignature(t *testing.T) {
	issuer := NewSessions("a-sufficiently-long-jwt-secret", time.Hour)
	other := NewSessions("an-entirely-different-jwt-secret", time.Hour)

	token, _, _ := issuer.Issue(uuid.New(), "alice", false)

	if _, err := other.Verify(token); err == nil {
		t.Fatal("a token signed with another secret was accepted")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	s := NewSessions("a-sufficiently-long-jwt-secret", -time.Minute)

	token, _, _ := s.Issue(uuid.New(), "alice", false)

	if _, err := s.Verify(token); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	s := NewSessions("a-sufficiently-long-jwt-secret", time.Hour)

	if _, err := s.Verify("not.a.jwt"); err == nil {
		t.Fatal("garbage was accepted as a session")
	}
}
