package auth

import (
	"slices"
	"testing"
)

func TestSanitizeDropsUnknownAndDuplicates(t *testing.T) {
	got := Sanitize([]string{"secrets:read", "not-a-permission", "secrets:read", "users:manage"})
	want := []string{"secrets:read", "users:manage"}

	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSanitizeReturnsCanonicalOrder(t *testing.T) {
	got := Sanitize([]string{"users:manage", "secrets:read"})

	if !slices.Equal(got, []string{"secrets:read", "users:manage"}) {
		t.Fatalf("permissions were not reordered canonically: %v", got)
	}
}

func TestSubset(t *testing.T) {
	have := []string{"secrets:read", "secrets:create"}

	if !Subset([]string{"secrets:read"}, have) {
		t.Fatal("expected a subset to be accepted")
	}
	if Subset([]string{"secrets:read", "users:manage"}, have) {
		t.Fatal("expected an over-broad set to be rejected")
	}
	if !Subset(nil, have) {
		t.Fatal("the empty set is a subset of everything")
	}
}

func TestDefaultsAreValid(t *testing.T) {
	for _, p := range Defaults {
		if !Valid(p) {
			t.Fatalf("default permission %q is not in the catalog", p)
		}
	}
}
