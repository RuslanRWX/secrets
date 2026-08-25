package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// handleListTokens shows all tokens to admins and only their own to everyone else.
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	scope := p.UserID()
	if p.IsAdmin && p.Token == nil {
		scope = nil
	}

	tokens, err := s.store.ListTokens(r.Context(), scope)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

type createTokenRequest struct {
	Name string `json:"name"`
	// UserID and GroupID are mutually exclusive; both empty means "issue to me".
	UserID  string   `json:"userId"`
	GroupID string   `json:"groupId"`
	Scopes  []string `json:"scopes"`
	// ExpiresInDays of 0 means the token never expires.
	ExpiresInDays int `json:"expiresInDays"`
}

// handleCreateToken mints an API token. The plaintext is returned exactly once.
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.User == nil {
		forbidden(w, "a group token cannot mint further tokens")

		return
	}

	var req createTokenRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		badRequest(w, "token name is required")

		return
	}
	if req.UserID != "" && req.GroupID != "" {
		badRequest(w, "a token belongs to either a user or a group, not both")

		return
	}

	scopes := auth.Sanitize(req.Scopes)
	if len(scopes) == 0 {
		badRequest(w, "at least one valid scope is required")

		return
	}

	newToken := store.NewToken{
		Name:      req.Name,
		Scopes:    scopes,
		CreatedBy: p.User.ID,
	}

	switch {
	case req.GroupID != "":
		groupID, ok := pathUUID(w, req.GroupID)
		if !ok {
			return
		}

		// Group tokens are shared machine credentials, so they need either
		// administrative rights or management of that specific group.
		allowed, err := s.canManageGroup(r, p, groupID)
		if err != nil {
			s.serverError(w, r, err)

			return
		}
		if !allowed {
			forbidden(w, "you must be an administrator or a manager of this group")

			return
		}
		if _, err := s.store.GroupByID(r.Context(), groupID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				badRequest(w, "that group does not exist")

				return
			}
			s.serverError(w, r, err)

			return
		}

		newToken.GroupID = &groupID

	case req.UserID != "":
		userID, ok := pathUUID(w, req.UserID)
		if !ok {
			return
		}

		if userID != p.User.ID && !p.IsAdmin {
			forbidden(w, "only an administrator can issue a token for another user")

			return
		}

		target, err := s.store.UserByID(r.Context(), userID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				badRequest(w, "that user does not exist")

				return
			}
			s.serverError(w, r, err)

			return
		}
		if !auth.Subset(scopes, effectivePermissions(target)) {
			badRequest(w, "the requested scopes exceed the permissions held by that user")

			return
		}

		newToken.UserID = &userID

	default:
		// Self-issued: the token can never exceed what the caller holds today.
		if !auth.Subset(scopes, effectivePermissions(p.User)) {
			forbidden(w, "you cannot grant a token scopes beyond your own permissions")

			return
		}

		newToken.UserID = &p.User.ID
	}

	if req.ExpiresInDays < 0 || req.ExpiresInDays > 3650 {
		badRequest(w, "expiresInDays must be between 0 and 3650")

		return
	}
	if req.ExpiresInDays > 0 {
		expiry := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		newToken.ExpiresAt = &expiry
	}

	minted, err := auth.MintToken()
	if err != nil {
		s.serverError(w, r, err)

		return
	}
	newToken.Prefix = minted.Prefix
	newToken.Hash = minted.Hash

	token, err := s.store.CreateToken(r.Context(), newToken)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "token.created", "token", token.ID.String(), map[string]any{
		"name": token.Name, "scopes": token.Scopes,
		"userId": token.UserID, "groupId": token.GroupID,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token,
		// Shown once; the server keeps only a hash.
		"plaintext": minted.Plaintext,
	})
}

// handleRevokeToken disables a token immediately.
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	scope := p.UserID()
	if p.IsAdmin && p.Token == nil {
		scope = nil
	}

	if err := s.store.RevokeToken(r.Context(), id, scope); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "token.revoked", "token", id.String(), nil)

	w.WriteHeader(http.StatusNoContent)
}

// handleAudit returns the most recent audit entries.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	entries, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}
