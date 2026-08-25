package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

type contextKey string

const principalKey contextKey = "principal"

// Principal is the authenticated caller: either a signed-in user, a user-bound
// API token acting on their behalf, or a group-bound API token.
type Principal struct {
	User        *store.User
	Token       *store.APIToken
	Permissions []string
	IsAdmin     bool
	GroupID     *uuid.UUID
}

// Label describes the principal for the audit log.
func (p *Principal) Label() string {
	switch {
	case p.Token != nil && p.User != nil:
		return p.User.Username + " (token " + p.Token.Name + ")"
	case p.Token != nil:
		return "group:" + p.Token.GroupName + " (token " + p.Token.Name + ")"
	case p.User != nil:
		return p.User.Username
	default:
		return "anonymous"
	}
}

// UserID returns the acting user's ID, or nil for a group token.
func (p *Principal) UserID() *uuid.UUID {
	if p.User == nil {
		return nil
	}

	return &p.User.ID
}

// TokenID returns the API token's ID when one was used.
func (p *Principal) TokenID() *uuid.UUID {
	if p.Token == nil {
		return nil
	}

	return &p.Token.ID
}

// Actor converts the principal into the store's access-control actor.
func (p *Principal) Actor() store.Actor {
	return store.Actor{UserID: p.UserID(), GroupID: p.GroupID, IsAdmin: p.IsAdmin}
}

// Can reports whether the principal holds a permission. Admins hold all of them,
// except that an API token is still limited to the scopes it was issued with.
func (p *Principal) Can(permission string) bool {
	if p.Token == nil && p.IsAdmin {
		return true
	}

	return slices.Contains(p.Permissions, permission)
}

func principalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey).(*Principal)

	return p
}

// authenticate resolves the credential on the request and rejects anonymous callers.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("Authorization"))
		if raw == "" {
			unauthorized(w, "authentication is required")

			return
		}

		scheme, credential, found := strings.Cut(raw, " ")
		if !found || !strings.EqualFold(scheme, "bearer") {
			unauthorized(w, "expected an Authorization: Bearer header")

			return
		}

		var (
			principal *Principal
			err       error
		)
		if strings.HasPrefix(credential, auth.TokenPrefixLabel+"_") {
			principal, err = s.principalFromAPIToken(r.Context(), credential)
		} else {
			principal, err = s.principalFromSession(r.Context(), credential)
		}
		if err != nil {
			if errors.Is(err, errUnauthenticated) {
				unauthorized(w, "credential is invalid, expired or revoked")

				return
			}
			s.serverError(w, r, err)

			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
	})
}

var errUnauthenticated = errors.New("unauthenticated")

func (s *Server) principalFromSession(ctx context.Context, credential string) (*Principal, error) {
	userID, err := s.sessions.Verify(credential)
	if err != nil {
		return nil, errUnauthenticated
	}

	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errUnauthenticated
		}

		return nil, err
	}
	if !user.IsActive {
		return nil, errUnauthenticated
	}

	return &Principal{User: user, Permissions: user.Permissions, IsAdmin: user.IsAdmin}, nil
}

func (s *Server) principalFromAPIToken(ctx context.Context, credential string) (*Principal, error) {
	prefix, err := auth.SplitToken(credential)
	if err != nil {
		return nil, errUnauthenticated
	}

	token, hash, err := s.store.TokenByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errUnauthenticated
		}

		return nil, err
	}

	if subtle.ConstantTimeCompare(hash, auth.HashToken(credential)) != 1 {
		return nil, errUnauthenticated
	}
	if token.RevokedAt != nil {
		return nil, errUnauthenticated
	}
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		return nil, errUnauthenticated
	}

	principal := &Principal{Token: token, Permissions: token.Scopes}

	if token.UserID != nil {
		user, err := s.store.UserByID(ctx, *token.UserID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, errUnauthenticated
			}

			return nil, err
		}
		if !user.IsActive {
			return nil, errUnauthenticated
		}

		// A token can never outgrow the permissions its owner currently holds,
		// so revoking a user's permission immediately narrows their tokens too.
		principal.User = user
		principal.IsAdmin = user.IsAdmin
		principal.Permissions = intersect(token.Scopes, effectivePermissions(user))
	} else {
		principal.GroupID = token.GroupID
	}

	if err := s.store.TouchToken(ctx, token.ID); err != nil {
		s.log.Warn("record token use", "token", token.ID, "error", err)
	}

	return principal, nil
}

// effectivePermissions expands an admin account to the full permission set.
func effectivePermissions(u *store.User) []string {
	if u.IsAdmin {
		return auth.All
	}

	return u.Permissions
}

func intersect(a, b []string) []string {
	out := make([]string, 0, len(a))
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}

	return out
}

// requirePermission blocks callers lacking a named permission.
func requirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := principalFrom(r.Context()); p == nil || !p.Can(permission) {
				forbidden(w, "this action requires the "+permission+" permission")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// requireAdmin blocks anyone who is not an administrator.
func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := principalFrom(r.Context()); p == nil || !p.IsAdmin {
			forbidden(w, "this action is restricted to administrators")

			return
		}

		next.ServeHTTP(w, r)
	})
}

// requirePasswordChanged forces a first-login password change before anything else.
func requirePasswordChanged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		if p != nil && p.User != nil && p.User.MustChangePassword && p.Token == nil {
			writeError(w, http.StatusForbidden, "password_change_required",
				"you must choose a new password before using the application")

			return
		}

		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the caller address, honouring proxy headers when configured.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.Split(fwd, ",")[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}
