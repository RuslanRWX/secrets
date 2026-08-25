package auth

import "slices"

// Permission flags an admin can grant to a user. A token may only carry a
// subset of the permissions held by the user that owns it.
const (
	PermSecretsRead   = "secrets:read"
	PermSecretsCreate = "secrets:create"
	PermSecretsUpdate = "secrets:update"
	PermSecretsDelete = "secrets:delete"
	PermSecretsShare  = "secrets:share"
	PermGroupsCreate  = "groups:create"
	PermGroupsManage  = "groups:manage"
	PermTokensCreate  = "tokens:create"
	PermUsersManage   = "users:manage"
	PermAuditRead     = "audit:read"
)

// All lists every assignable permission, in the order the UI presents them.
var All = []string{
	PermSecretsRead,
	PermSecretsCreate,
	PermSecretsUpdate,
	PermSecretsDelete,
	PermSecretsShare,
	PermGroupsCreate,
	PermGroupsManage,
	PermTokensCreate,
	PermUsersManage,
	PermAuditRead,
}

// Defaults are granted to a new user unless the admin picks something else.
var Defaults = []string{PermSecretsRead, PermSecretsCreate, PermSecretsUpdate, PermSecretsShare}

// Valid reports whether name is a known permission.
func Valid(name string) bool { return slices.Contains(All, name) }

// Sanitize drops unknown and duplicate permissions, preserving canonical order.
func Sanitize(perms []string) []string {
	out := make([]string, 0, len(perms))
	for _, p := range All {
		if slices.Contains(perms, p) {
			out = append(out, p)
		}
	}

	return out
}

// Subset reports whether every permission in want is present in have.
func Subset(want, have []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}

	return true
}
