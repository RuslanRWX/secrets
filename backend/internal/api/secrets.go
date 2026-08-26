package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ruslanrwx/secrets/backend/internal/auth"
	"github.com/ruslanrwx/secrets/backend/internal/cryptoutil"
	"github.com/ruslanrwx/secrets/backend/internal/store"
)

// maxSecretBytes caps a stored value; passwords and config blobs stay well under it.
const maxSecretBytes = 64 * 1024

// handleListSecrets returns metadata for every secret the caller can read.
// Values are never included: fetching one is a separate, audited call.
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	secrets, err := s.store.ListSecrets(r.Context(), p.Actor())
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"secrets": secrets})
}

type createSecretRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
	Username    string `json:"username"`
	URL         string `json:"url"`
	Value       string `json:"value"`
	// ShareWith optionally shares the new secret with groups in the same call.
	ShareWith []shareRequest `json:"shareWith"`
}

type shareRequest struct {
	// Exactly one of GroupID or UserID identifies who is being given access.
	GroupID  string `json:"groupId"`
	UserID   string `json:"userId"`
	CanWrite bool   `json:"canWrite"`
}

// handleCreateSecret seals a value and stores it under the caller's ownership.
func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.User == nil {
		forbidden(w, "a group token cannot create secrets")

		return
	}

	var req createSecretRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		badRequest(w, "name is required")

		return
	}
	if req.Value == "" {
		badRequest(w, "value is required")

		return
	}
	if len(req.Value) > maxSecretBytes {
		badRequest(w, "value is too large")

		return
	}

	kind := req.Kind
	if kind == "" {
		kind = "password"
	}
	if kind != "password" && kind != "text" {
		badRequest(w, `kind must be either "password" or "text"`)

		return
	}

	wrappedDEK, ciphertext, err := s.keys.Seal([]byte(req.Value))
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	secret, err := s.store.CreateSecret(r.Context(), store.NewSecret{
		Name:        req.Name,
		Description: req.Description,
		Kind:        kind,
		Username:    req.Username,
		URL:         req.URL,
		OwnerID:     p.User.ID,
		CreatedBy:   p.User.ID,
		KeyID:       s.keys.KeyID(),
		WrappedDEK:  wrappedDEK,
		Ciphertext:  ciphertext,
	})
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	for _, share := range req.ShareWith {
		if err := s.applyShare(r, p, secret.ID, share); err != nil {
			s.log.Warn("share new secret", "secret", secret.ID, "error", err)
		}
	}

	s.audit(r, p, "secret.created", "secret", secret.ID.String(), map[string]any{"name": secret.Name})

	fresh, err := s.store.SecretByID(r.Context(), secret.ID, p.Actor())
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusCreated, fresh)
}

// handleGetSecret returns metadata for a single secret.
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	secret, err := s.store.SecretByID(r.Context(), id, p.Actor())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, secret)
}

// handleRevealSecret decrypts and returns a value. Every call is audited.
func (s *Server) handleRevealSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	wrappedDEK, ciphertext, err := s.store.SecretCipher(r.Context(), id, p.Actor())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	plaintext, err := s.keys.Open(wrappedDEK, ciphertext)
	if err != nil {
		if errors.Is(err, cryptoutil.ErrWrongKey) {
			s.log.Error("cannot decrypt secret with the configured master key", "secret", id)
			writeError(w, http.StatusInternalServerError, "key_mismatch",
				"this secret was encrypted with a different master key")

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "secret.revealed", "secret", id.String(), nil)

	// Decrypted material must never be cached by a browser or a proxy.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "value": string(plaintext)})
}

type updateSecretRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Username    *string `json:"username"`
	URL         *string `json:"url"`
	Value       *string `json:"value"`
}

// handleUpdateSecret edits labels and, when a value is supplied, rotates it.
func (s *Server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	var req updateSecretRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	if req.Value != nil {
		if *req.Value == "" {
			badRequest(w, "value cannot be empty")

			return
		}
		if len(*req.Value) > maxSecretBytes {
			badRequest(w, "value is too large")

			return
		}

		wrappedDEK, ciphertext, err := s.keys.Seal([]byte(*req.Value))
		if err != nil {
			s.serverError(w, r, err)

			return
		}

		if _, err := s.store.RotateValue(r.Context(), id, p.Actor(), s.keys.KeyID(),
			wrappedDEK, ciphertext, p.UserID()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				notFound(w)

				return
			}
			s.serverError(w, r, err)

			return
		}

		s.audit(r, p, "secret.value_rotated", "secret", id.String(), nil)
	}

	secret, err := s.store.UpdateSecretMeta(r.Context(), id, p.Actor(), store.SecretMetaUpdate{
		Name:        req.Name,
		Description: req.Description,
		Username:    req.Username,
		URL:         req.URL,
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "secret.updated", "secret", id.String(), map[string]any{"name": secret.Name})

	writeJSON(w, http.StatusOK, secret)
}

// handleDeleteSecret removes a secret and all of its versions.
func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	if err := s.store.DeleteSecret(r.Context(), id, p.Actor()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "secret.deleted", "secret", id.String(), nil)

	w.WriteHeader(http.StatusNoContent)
}

// handleSecretVersions lists the value history of a secret.
func (s *Server) handleSecretVersions(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	if _, err := s.store.SecretByID(r.Context(), id, p.Actor()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	versions, err := s.store.SecretVersions(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

// handleShareSecret grants a group or a single person access to a secret.
func (s *Server) handleShareSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	var req shareRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())

		return
	}

	if (req.GroupID == "") == (req.UserID == "") {
		badRequest(w, "name either a groupId or a userId, not both and not neither")

		return
	}

	if err := s.applyShare(r, p, id, req); err != nil {
		s.shareError(w, r, err)

		return
	}

	detail := map[string]any{"canWrite": req.CanWrite}
	if req.GroupID != "" {
		detail["groupId"] = req.GroupID
	} else {
		detail["userId"] = req.UserID
	}
	s.audit(r, p, "secret.shared", "secret", id.String(), detail)

	secret, err := s.store.SecretByID(r.Context(), id, p.Actor())
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, secret)
}

// shareError maps the sharing failures onto responses.
func (s *Server) shareError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		notFound(w)
	case errors.Is(err, errNotSecretOwner):
		forbidden(w, "only the owner or an administrator can share this secret")
	case errors.Is(err, errNotGroupMember):
		forbidden(w, "you can only share with groups you belong to")
	case errors.Is(err, errShareTargetMissing):
		badRequest(w, "that user or group does not exist")
	case errors.Is(err, errShareWithOwner):
		badRequest(w, "this person already owns the secret")
	default:
		s.serverError(w, r, err)
	}
}

var (
	errNotSecretOwner     = errors.New("not the owner of this secret")
	errNotGroupMember     = errors.New("not a member of this group")
	errShareTargetMissing = errors.New("share target does not exist")
	errShareWithOwner     = errors.New("cannot share a secret with its own owner")
)

// applyShare grants access to one group or one person, after checking that the
// caller may share this secret at all.
func (s *Server) applyShare(r *http.Request, p *Principal, secretID uuid.UUID, share shareRequest) error {
	if p.User == nil {
		return errNotSecretOwner
	}

	if !p.IsAdmin {
		owned, err := s.store.IsSecretOwner(r.Context(), secretID, p.User.ID)
		if err != nil {
			return err
		}
		if !owned {
			return errNotSecretOwner
		}
	}

	if share.UserID != "" {
		userID, err := uuid.Parse(share.UserID)
		if err != nil {
			return errShareTargetMissing
		}

		target, err := s.store.UserByID(r.Context(), userID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errShareTargetMissing
			}

			return err
		}

		// Sharing with the owner would create a redundant row that the access
		// rules already cover, and reads as a mistake in the interface.
		owner, err := s.store.SecretOwner(r.Context(), secretID)
		if err != nil {
			return err
		}
		if owner != nil && *owner == target.ID {
			return errShareWithOwner
		}

		return s.store.ShareSecretWithUser(r.Context(), secretID, userID, share.CanWrite, p.User.ID)
	}

	groupID, err := uuid.Parse(share.GroupID)
	if err != nil {
		return errShareTargetMissing
	}

	if !p.IsAdmin {
		// Sharing into a group you are not in would give away access you cannot see.
		role, err := s.store.GroupRole(r.Context(), groupID, p.User.ID)
		if err != nil {
			return err
		}
		if role == "" && !p.Can(auth.PermGroupsManage) {
			return errNotGroupMember
		}
	}

	if _, err := s.store.GroupByID(r.Context(), groupID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errShareTargetMissing
		}

		return err
	}

	return s.store.ShareSecret(r.Context(), secretID, groupID, share.CanWrite, p.User.ID)
}

// handleUnshareGroup revokes a group's access.
func (s *Server) handleUnshareGroup(w http.ResponseWriter, r *http.Request) {
	s.unshare(w, r, "groupID", func(secretID, groupID uuid.UUID) error {
		return s.store.UnshareSecret(r.Context(), secretID, groupID)
	})
}

// handleUnshareUser revokes one person's direct access.
func (s *Server) handleUnshareUser(w http.ResponseWriter, r *http.Request) {
	s.unshare(w, r, "userID", func(secretID, userID uuid.UUID) error {
		return s.store.UnshareSecretFromUser(r.Context(), secretID, userID)
	})
}

// unshare holds the permission check both revoke endpoints share.
func (s *Server) unshare(w http.ResponseWriter, r *http.Request, param string, revoke func(secretID, targetID uuid.UUID) error) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	targetID, ok := pathUUID(w, chi.URLParam(r, param))
	if !ok {
		return
	}

	if p.User == nil {
		forbidden(w, "a group token cannot change sharing")

		return
	}

	if !p.IsAdmin {
		owned, err := s.store.IsSecretOwner(r.Context(), id, p.User.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				notFound(w)

				return
			}
			s.serverError(w, r, err)

			return
		}
		if !owned {
			forbidden(w, "only the owner or an administrator can change sharing")

			return
		}
	}

	if err := revoke(id, targetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "secret.unshared", "secret", id.String(), map[string]any{param: targetID.String()})

	w.WriteHeader(http.StatusNoContent)
}
