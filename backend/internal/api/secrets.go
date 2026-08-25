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
	GroupID  string `json:"groupId"`
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
		groupID, err := uuid.Parse(share.GroupID)
		if err != nil {
			continue
		}
		if err := s.shareOne(r, p, secret.ID, groupID, share.CanWrite); err != nil {
			s.log.Warn("share new secret", "secret", secret.ID, "group", groupID, "error", err)
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

// handleShareSecret grants a group access to a secret the caller owns.
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

	groupID, ok := pathUUID(w, req.GroupID)
	if !ok {
		return
	}

	if err := s.shareOne(r, p, id, groupID, req.CanWrite); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			notFound(w)
		case errors.Is(err, errNotSecretOwner):
			forbidden(w, "only the owner or an administrator can share this secret")
		case errors.Is(err, errNotGroupMember):
			forbidden(w, "you can only share with groups you belong to")
		default:
			s.serverError(w, r, err)
		}

		return
	}

	s.audit(r, p, "secret.shared", "secret", id.String(),
		map[string]any{"groupId": groupID.String(), "canWrite": req.CanWrite})

	secret, err := s.store.SecretByID(r.Context(), id, p.Actor())
	if err != nil {
		s.serverError(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, secret)
}

var (
	errNotSecretOwner = errors.New("not the owner of this secret")
	errNotGroupMember = errors.New("not a member of this group")
)

// shareOne applies one share after checking ownership and group membership.
func (s *Server) shareOne(r *http.Request, p *Principal, secretID, groupID uuid.UUID, canWrite bool) error {
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

		// Sharing into a group you are not in would give away access you cannot see.
		role, err := s.store.GroupRole(r.Context(), groupID, p.User.ID)
		if err != nil {
			return err
		}
		if role == "" && !p.Can(auth.PermGroupsManage) {
			return errNotGroupMember
		}
	}

	return s.store.ShareSecret(r.Context(), secretID, groupID, canWrite, p.User.ID)
}

// handleUnshareSecret revokes a group's access.
func (s *Server) handleUnshareSecret(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	id, ok := pathUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	groupID, ok := pathUUID(w, chi.URLParam(r, "groupID"))
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

	if err := s.store.UnshareSecret(r.Context(), id, groupID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w)

			return
		}
		s.serverError(w, r, err)

		return
	}

	s.audit(r, p, "secret.unshared", "secret", id.String(), map[string]any{"groupId": groupID.String()})

	w.WriteHeader(http.StatusNoContent)
}
