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

// A group token acts as the group itself, so it must never be able to carry a
// permission that only makes sense for a person.
func TestGroupTokenScopesExcludeUserOnlyPowers(t *testing.T) {
	forbidden := []string{
		PermUsersManage, PermGroupsCreate, PermGroupsManage,
		PermTokensCreate, PermAuditRead, PermSecretsCreate, PermSecretsShare,
	}

	for _, permission := range forbidden {
		if ValidForGroupToken(permission) {
			t.Errorf("%q must not be grantable to a group token", permission)
		}
	}

	for _, permission := range GroupTokenScopes {
		if !Valid(permission) {
			t.Errorf("%q is not in the permission catalog", permission)
		}
	}
}
