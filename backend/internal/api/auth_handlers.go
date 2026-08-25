package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin exchanges credentials for a session token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	user, err := s.store.UserByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Spend the same work as a real verification so timing does not leak
			// whether the username exists.
			_, _ = cryptoutil.HashPassword(req.Password)
			unauthorized(w, "username or password is incorrect")

			return
		}
		s.serverError(w, r, err)

		return
	}

	ok, err := cryptoutil.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !ok {
		s.audit(r, &Principal{User: user}, "auth.login_failed", "user", user.ID.String(), nil)
		unauthorized(w, "username or password is incorrect")

		return
	}
	if !user.IsActive {
		forbidden(w, "this account is disabled")

		return
	}

	token, expiry, err := s.sessions.Issue(user.ID, user.Username, user.IsAdmin)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	if err := s.store.TouchLogin(r.Context(), user.ID); err != nil {
		s.log.Warn("record login", "user", user.ID, "error", err)
	}

	s.audit(r, &Principal{User: user, IsAdmin: user.IsAdmin}, "auth.login", "user", user.ID.String(), nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":              token,
		"expiresAt":          expiry,
		"user":               user,
		"mustChangePassword": user.MustChangePassword,
	})
}

// handleMe returns the current principal.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	body := map[string]any{
		"permissions": p.Permissions,
		"isAdmin":     p.IsAdmin,
	}
	if p.User != nil {
		body["user"] = p.User
		body["mustChangePassword"] = p.User.MustChangePassword
	}
	if p.Token != nil {
		body["token"] = p.Token
	}

	writeJSON(w, http.StatusOK, body)
}

type updateProfileRequest struct {
	Email *string `json:"email"`
}

// handleUpdateProfile lets a signed-in user change their own email address.
// Display name, roles and permissions are deliberately not reachable here:
// those stay with an administrator.
func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.User == nil {
		forbidden(w, "an API token cannot edit a profile")

		return
	}

	var req updateProfileRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	if req.Email != nil {
		trimmed := strings.TrimSpace(*req.Email)
		if trimmed != "" && !strings.Contains(trimmed, "@") {
			badRequest(w, "that does not look like an email address")

			return
		}
		req.Email = &trimmed
	}
	user, err := s.store.UpdateUser(r.Context(), p.User.ID, store.UserUpdate{
		Email: req.Email,
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "user.email_changed", "user", p.User.ID.String(), nil)

	writeJSON(w, http.StatusOK, user)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// handleChangePassword lets a signed-in user rotate their own password. This is
// the endpoint a first-login user is forced through.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.User == nil {
		forbidden(w, "an API token cannot change a password")

		return
	}

	var req changePasswordRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	ok, err := cryptoutil.VerifyPassword(p.User.PasswordHash, req.CurrentPassword)
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	if !ok {
		unauthorized(w, "current password is incorrect")

		return
	}

	if problem := validatePassword(req.NewPassword); problem != "" {
		badRequest(w, problem)

		return
	}
	if req.NewPassword == req.CurrentPassword {
		badRequest(w, "new password must differ from the current one")

		return
	}

	hash, err := cryptoutil.HashPassword(req.NewPassword)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	if err := s.store.SetPassword(r.Context(), p.User.ID, hash, false); err != nil {
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "auth.password_changed", "user", p.User.ID.String(), nil)

	writeJSON(w, http.StatusOK, map[string]any{"status": "password updated"})
}
