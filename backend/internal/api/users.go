package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// publicUser is the trimmed view non-admins get when listing users, which is
// only enough to pick people for group membership.
type publicUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	IsActive    bool   `json:"isActive"`
}

// handleListUsers returns full records to admins and a directory view to everyone else.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	if p.Can(auth.PermUsersManage) {
		writeJSON(w, http.StatusOK, map[string]any{"users": users})

		return
	}

	directory := make([]publicUser, 0, len(users))
	for _, u := range users {
		directory = append(directory, publicUser{
			ID: u.ID.String(), Username: u.Username, DisplayName: u.DisplayName, IsActive: u.IsActive,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": directory})
}

type createUserRequest struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	IsAdmin     bool     `json:"isAdmin"`
	Permissions []string `json:"permissions"`
}

// handleCreateUser adds an account with an initial password the user must replace.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	var req createUserRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		badRequest(w, "username is required")

		return
	}
	if problem := validatePassword(req.Password); problem != "" {
		badRequest(w, problem)

		return
	}
	if req.IsAdmin && !p.IsAdmin {
		forbidden(w, "only an administrator can create another administrator")

		return
	}

	permissions := auth.Sanitize(req.Permissions)
	if len(permissions) == 0 {
		permissions = auth.Defaults
	}
	// A non-admin with users:manage cannot hand out permissions they lack themselves.
	if !p.IsAdmin && !auth.Subset(permissions, p.Permissions) {
		forbidden(w, "you cannot grant permissions that you do not hold")

		return
	}

	hash, err := cryptoutil.HashPassword(req.Password)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	user, err := s.store.CreateUser(r.Context(), &store.User{
		Username:           req.Username,
		Email:              strings.TrimSpace(req.Email),
		DisplayName:        strings.TrimSpace(req.DisplayName),
		PasswordHash:       hash,
		IsAdmin:            req.IsAdmin,
		IsActive:           true,
		MustChangePassword: true, // Enforced on first sign-in.
		Permissions:        permissions,
	})
	if err != nil {
		if isUniqueViolation(err) {
			conflict(w, "a user with that username already exists")

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "user.created", "user", user.ID.String(), map[string]any{
		"username": user.Username, "isAdmin": user.IsAdmin, "permissions": user.Permissions,
	})

	writeJSON(w, http.StatusCreated, user)
}

type updateUserRequest struct {
	Email       *string   `json:"email"`
	DisplayName *string   `json:"displayName"`
	IsAdmin     *bool     `json:"isAdmin"`
	IsActive    *bool     `json:"isActive"`
	Permissions *[]string `json:"permissions"`
}

// handleUpdateUser changes profile fields, the admin flag and permissions.
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	var req updateUserRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	if (req.IsAdmin != nil || req.Permissions != nil) && !p.IsAdmin {
		forbidden(w, "only an administrator can change roles or permissions")

		return
	}

	// Never let the last active admin lose their access.
	if demotesAdmin(req) {
		target, err := s.store.UserByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				notFound(w)

				return
			}
			s.serverError(w, r, err)

			return
		}

		if target.IsAdmin && target.IsActive {
			admins, err := s.store.CountAdmins(r.Context())
			if err != nil {
				s.serverError(w, r, err)

				return
			}
			if admins <= 1 {
				conflict(w, "this is the last active administrator")

				return
			}
		}
	}

	if req.Permissions != nil {
		sanitized := auth.Sanitize(*req.Permissions)
		req.Permissions = &sanitized
	}

	user, err := s.store.UpdateUser(r.Context(), id, store.UserUpdate{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		IsAdmin:     req.IsAdmin,
		IsActive:    req.IsActive,
		Permissions: req.Permissions,
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "user.updated", "user", user.ID.String(), map[string]any{
		"permissions": user.Permissions, "isAdmin": user.IsAdmin, "isActive": user.IsActive,
	})

	writeJSON(w, http.StatusOK, user)
}

// demotesAdmin reports whether the update could strip administrative access.
func demotesAdmin(req updateUserRequest) bool {
	return (req.IsAdmin != nil && !*req.IsAdmin) || (req.IsActive != nil && !*req.IsActive)
}

// handleDeleteUser removes an account along with the secrets it owns.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	if p.User != nil && p.User.ID == id {
		conflict(w, "you cannot delete your own account")

		return
	}

	target, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	if target.IsAdmin && target.IsActive {
		admins, err := s.store.CountAdmins(r.Context())
		if err != nil {
			s.serverError(w, r, err)

			return
		}
		if admins <= 1 {
			conflict(w, "this is the last active administrator")

			return
		}
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "user.deleted", "user", id.String(), map[string]any{"username": target.Username})

	w.WriteHeader(http.StatusNoContent)
}

type resetPasswordRequest struct {
	NewPassword string `json:"newPassword"`
}

// handleResetPassword sets a temporary password the user must change at next sign-in.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	var req resetPasswordRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}
	if problem := validatePassword(req.NewPassword); problem != "" {
		badRequest(w, problem)

		return
	}

	if _, err := s.store.UserByID(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	hash, err := cryptoutil.HashPassword(req.NewPassword)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	if err := s.store.SetPassword(r.Context(), id, hash, true); err != nil {
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "user.password_reset", "user", id.String(), nil)

	writeJSON(w, http.StatusOK, map[string]any{"status": "password reset; the user must change it at next sign-in"})
}

// isUniqueViolation reports whether err is a PostgreSQL duplicate-key error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
